# Coupon Usage Count on Cancellation: Issue & Implementation of Fix

This document details the coupon deduction issue and the exact backend and frontend implementation required to replicate the fix in another codebase.

---

## 1. The Issue

### Why the count decreased before payment:
When a customer clicks **"Pay Online"**:
* The backend creates the order with `orderStatus: "PROCESSING"` and `paymentStatus: "PENDING"`.
* In that **same initial database transaction** (before the customer even enters payment details), the backend consumes the coupon:
  ```ts
  if (resolvedCouponId) {
    await tx.coupon.update({
      where: { id: resolvedCouponId },
      data: { usedCount: { increment: 1 } },
    });
  }
  ```

### Why it was not restored on cancellation:
When the customer closes the payment popup, payment fails, or the order is cancelled:
* The backend runs the cancellation rollback (`restoreStockNow`).
* This function returned **product stock** back to inventory, but **completely omitted coupon restoration**. The coupon's `usedCount` remained permanently incremented by 1.

### Why the admin panel showed "Expired":
In the admin coupon management table (`CouponManagement.tsx`):
```ts
const isExpired = (c: Coupon) =>
  (c.expiresAt != null && new Date(c.expiresAt) < new Date()) ||
  (c.maxUses != null && c.usedCount >= c.maxUses);
```
If a coupon has `Max Uses: 1`, as soon as `usedCount` becomes `1`, the check `usedCount >= maxUses` (`1 >= 1`) evaluates to `true`. The UI labels an exhausted coupon as **"Expired"**, even though the date has not passed.

---

## 2. Cancellation Architecture

Orders can be cancelled through 4 distinct entry points:
1. **Customer closes payment popup / aborts payment** (`POST /api/order/cancel/:id` -> `cancelOrder`)
2. **Payment Gateway Webhook failure** (`POST /api/order/razorpay-webhook` -> `handleRazorpayWebhook`)
3. **Admin manual cancellation** (`PUT /api/orders/update-status/:id` -> `updateStatus`)
4. **Background maintenance cron** (`cleanupAbandonedOrders` for uncompleted sessions older than 30 mins)

All 4 pathways route to a single rollback function: **`restoreStockNow()`** in `backend/src/services/inventory.service.ts`.  
Placing the coupon restoration here fixes all 4 cancellation scenarios in one place.

---

## 3. Backend Implementation

### File: `backend/src/services/inventory.service.ts`

#### Step 1: Import the `Coupon` Model
```ts
import { Product, ProductVariant, Order, Coupon } from "../models/mongoose";
```

#### Step 2: Implement Coupon Restoration in `restoreStockNow()`
Inside `restoreStockNow(data: RestoreStockJobData)`, right after the atomic `Order.findOneAndUpdate` claim, add the coupon decrement logic:

```ts
const restoreStockNow = async (data: RestoreStockJobData) => {
  // 1. Atomic compare-and-swap (ensures rollback only executes ONCE per order)
  const claimed = await Order.findOneAndUpdate(
    { _id: data.orderId, stockRestored: { $ne: true } },
    { $set: { stockRestored: true } },
  );
  if (!claimed) {
    logger.info(`[inventory] restore-stock for order ${data.orderId} already applied — skipping (idempotent)`);
    return;
  }

  // 2. [FIX] Decrement coupon usage if a coupon was redeemed on this order
  if (claimed.couponId) {
    try {
      await Coupon.updateOne(
        { _id: claimed.couponId, usedCount: { $gt: 0 } }, // Prevents count from ever going below 0
        { $inc: { usedCount: -1 } }                        // Restores 1 usage back
      );
      logger.info(`[inventory] Restored coupon ${claimed.couponId} usage for cancelled order ${data.orderId}`);
    } catch (couponErr) {
      logger.error(`[inventory] Failed to restore coupon usage for order ${data.orderId}`, couponErr);
    }
  }

  // 3. Existing product inventory restoration continues...
  for (const item of data.items) {
    if (item.variantId) {
      await ProductVariant.updateOne({ _id: item.variantId }, { $inc: { stock: item.quantity } });
      await syncProductFromVariants(item.productId);
    } else {
      await Product.updateOne({ _id: item.productId }, { $inc: { stock: item.quantity } });
    }
  }
};
```

---

## 4. Frontend Implementation

### File: `frontend/src/cart/CheckoutPage.tsx`

When the customer dismisses the payment popup or payment fails, the frontend triggers the cancellation endpoint:

```tsx
let orderClosed = false;
const cancelPendingOrder = async () => {
  if (orderClosed || isPaymentSuccess.current) return;
  orderClosed = true;
  try {
    await api.post(`/order/cancel/${res.data.order.id}`);
  } catch (err) {
    console.error("Cancel failed", err);
  }
};

const options = {
  key: razorpayKey,
  amount: res.data.rzpOrder.amount,
  order_id: res.data.rzpOrder.id,
  handler: async (response: any) => {
    isPaymentSuccess.current = true;
    // ... verify payment
  },
  modal: {
    ondismiss: async function () {
      setIsRazorpayOpen(false);
      setLoading(false);
      if (isPaymentSuccess.current) return;
      // Trigger cancel when customer closes the modal without paying
      await cancelPendingOrder();
      toast.error("Payment cancelled.");
    },
  },
};

const rzp = new (window as any).Razorpay(options);

rzp.on("payment.failed", async function (response: any) {
  toast.error("Payment Failed");
  if (!isPaymentSuccess.current) {
    await cancelPendingOrder();
  }
});

rzp.open();
```

---

## 5. Why This Implementation Is Safe

1. **Idempotent (No Double Decrements):**  
   `Order.findOneAndUpdate({ _id: data.orderId, stockRestored: { $ne: true } }, { $set: { stockRestored: true } })` is an atomic compare-and-swap. Even if a user clicks cancel twice or a webhook arrives concurrently, only the **first** call gets a valid `claimed` document. Subsequent calls return immediately.
2. **Floored at Zero:**  
   The condition `{ usedCount: { $gt: 0 } }` guarantees that `usedCount` can **never become negative**.
3. **Isolated Error Handling:**  
   The coupon update is wrapped in its own `try/catch`. If a coupon was deleted by an admin, stock restoration continues unhindered.
4. **Universal Coverage:**  
   Because all 4 cancellation flows call `restoreStockNow()`, the coupon is restored whether the order was cancelled by the customer, by payment failure, by admin, or by automated background cleanup.

---

# Restricting Invoices for Cancelled Orders (Customer-Facing)

This section documents the requirement and full-stack implementation to prevent customers from viewing or downloading invoices for cancelled orders, while preserving administrative and accounting access for staff/admins.

---

## 1. Requirement & Problem Statement

### The Problem:
* Previously, customer-facing pages showed an **Invoice** or **View Invoice** action button for all orders, including those with `orderStatus: "CANCELLED"`.
* If a customer visited `/invoice/:orderId` directly or queried the order endpoint `GET /api/orders/:id`, the system rendered the complete invoice and receipt PDF controls even for cancelled orders.

### The Objective:
* Completely prevent customers from viewing, generating, or downloading invoices for cancelled orders.
* Hide invoice buttons on customer order and transaction views.
* Block customer direct access to `/invoice/:orderId` with a clear "Invoice Unavailable" message.
* Enforce backend API security on `GET /api/orders/:id` so customers cannot bypass the UI restriction.
* Keep invoice visibility intact for privileged roles (`ADMIN`, `SUPER_ADMIN`, `STAFF`) for audit, dispute resolution, tax, and bookkeeping requirements.

---

## 2. Full-Stack Architecture & Defense-in-Depth

The restriction is implemented across four distinct layers:

1. **Customer Orders View (`MyOrdersPage.tsx`)**: Hides the "Invoice" button on order cards if `orderStatus` is `CANCELLED`.
2. **Customer Transactions View (`TransactionHistory.tsx`)**: Hides the "View Invoice" button in expanded transaction details if `orderStatus` is `CANCELLED`.
3. **Invoice Page Guard (`InvoicePage.tsx`)**: Blocks page rendering if the authenticated user is a customer and the order is cancelled, showing an "Invoice Unavailable" state instead.
4. **Backend API Authorization (`order.controller.ts`)**: Enforces `403 Forbidden` on `GET /api/orders/:id` if a customer attempts to query a cancelled order.

---

## 3. Backend Implementation

### File: `backend/src/controllers/order.controller.ts`

In `getOrderById` (`GET /api/orders/:id`):

```ts
// Customers may only fetch their own orders
if (
  requestingUser.role !== Role.ADMIN &&
  requestingUser.role !== Role.SUPER_ADMIN &&
  requestingUser.role !== Role.STAFF &&
  order.userId !== requestingUser.id
) {
  return res.status(403).json({ message: "Not authorised" });
}

// Customers cannot view invoices for cancelled orders
if (
  requestingUser.role !== Role.ADMIN &&
  requestingUser.role !== Role.SUPER_ADMIN &&
  requestingUser.role !== Role.STAFF &&
  order.orderStatus?.toUpperCase() === "CANCELLED"
) {
  return res.status(403).json({ message: "Invoices are not available for cancelled orders." });
}
```

---

## 4. Frontend Implementation

### 1. File: `frontend/src/orders/MyOrdersPage.tsx`
Conditionally render the "Invoice" button only when the order status is not `CANCELLED`:

```tsx
<div className="flex items-center gap-2 self-start sm:self-center">
  <StatusBadge rawStatus={order.orderStatus} />
  {order.orderStatus?.toUpperCase() !== "CANCELLED" && (
    <button
      onClick={() => navigate(`/invoice/${order.id}`)}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-bold uppercase tracking-wider transition-all shadow-sm bg-white"
      style={{ borderColor: "var(--theme-primary)", color: "var(--theme-primary)" }}
      title="View Invoice"
    >
      <FileText className="w-3.5 h-3.5" />
      Invoice
    </button>
  )}
</div>
```

### 2. File: `frontend/src/pages/TransactionHistory.tsx`
Conditionally render the "View Invoice" button in `TransactionDetails` only when the transaction order status is not `CANCELLED`:

```tsx
{tx.orderStatus?.toUpperCase() !== "CANCELLED" && (
  <div className="flex justify-end pt-1">
    <button
      onClick={onViewInvoice}
      className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-bold uppercase tracking-wider shadow-sm transition-all text-center hover:brightness-110 active:scale-95 cursor-pointer"
      style={{ background: "var(--theme-primary)", color: "var(--theme-primary-ink)" }}
    >
      <Receipt className="w-3.5 h-3.5" />
      View Invoice
    </button>
  </div>
)}
```

### 3. File: `frontend/src/pages/InvoicePage.tsx`
Block invoice rendering for customers navigating directly to `/invoice/:orderId`:

```tsx
const isPrivileged = ["ADMIN", "SUPER_ADMIN", "STAFF"].includes(user?.role ?? "");
const isCancelledForCustomer = !isPrivileged && order?.orderStatus?.toUpperCase() === "CANCELLED";

if (error || !order || isCancelledForCustomer) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="max-w-md text-center p-8 bg-white rounded-2xl border border-gray-200 shadow">
        <XCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h2 className="text-lg font-bold text-gray-900 mb-2">
          {isCancelledForCustomer ? "Invoice Unavailable" : "Error"}
        </h2>
        <p className="text-gray-500 mb-6">
          {isCancelledForCustomer
            ? "Invoices are not available for cancelled orders."
            : error ?? "Order not found."}
        </p>
        <button
          onClick={() => navigate(-1)}
          className="px-6 py-2 bg-black text-white rounded-full text-sm font-bold uppercase tracking-wider hover:bg-gray-900 transition"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}
```

Also, capture API error responses if the backend rejects the request:
```tsx
api.get(`/order/${orderId}`)
  .then((res) => setOrder(res.data.order))
  .catch((err) => {
    const status = err?.response?.status;
    const msg = err?.response?.data?.message;
    if (msg) setError(msg);
    else if (status === 403) setError("You are not authorised to view this invoice.");
    else if (status === 404) setError("Order not found.");
    else setError("Failed to load invoice. Please try again.");
  })
  .finally(() => setLoading(false));
```

---

## 5. Verification & Testing

1. **Customer Order History**: Logged in as a customer, verified that orders in `PROCESSING`, `CONFIRMED`, `SHIPPED`, or `DELIVERED` status display the Invoice button, whereas orders with `CANCELLED` status do not show the button.
2. **Customer Transaction History**: Verified that expanded details for cancelled orders omit the "View Invoice" button.
3. **Direct URL Navigation**: Directly navigating to `/invoice/<cancelledOrderId>` as a customer renders the "Invoice Unavailable: Invoices are not available for cancelled orders." state.
4. **Backend API Direct Call**: Sending `GET /api/orders/<cancelledOrderId>` with a customer Bearer token returns `403 Forbidden`.
5. **Privileged Roles Unaffected**: Admins and staff can still view and print invoices for cancelled orders as required for accounting and records.

---

# UAE Mobile Number Validation for Admin & Staff

This section documents the update made to support UAE mobile numbers across the administrative user management interfaces and backend validation schemas.

---

## 1. Requirement & Problem Statement

### The Problem:
* Previously, the **Add New Admin** modal (`AddAdminModal.tsx`), **Add/Edit Staff** modal (`StaffManagement.tsx`), and **Edit User** modal (`Listusers.tsx`) strictly enforced 10-digit Indian mobile formats (`^[6-9][0-9]{9}$` or `^[0-9]{10}$`).
* The backend Zod schema (`staffCreateSchema` and `staffUpdateSchema` in `backend/src/schemas/staff.schema.ts`) also enforced `/^[6-9][0-9]{9}$/`, causing API rejection for any UAE mobile number.
* When admins in the UAE tried to enter standard 9-digit UAE mobile numbers (e.g., `527296567` or `0527296567`), the forms rejected the input with `"Enter a valid 10-digit phone number."` or `"Phone must be a valid 10-digit Indian mobile number."`.

### The Solution:
* Standardize mobile number validation across Admin & Staff workflows to accept UAE mobile numbers (`5xxxxxxxx`, `05xxxxxxxx`, `+9715xxxxxxxx`, `9715xxxxxxxx`) while retaining backward-compatibility for legacy 10-digit Indian numbers.
* Automatically normalize phone numbers (e.g. `0527296567` or `+971 52 729 6567` $\rightarrow$ canonical `527296567`) before saving to MongoDB / Prisma.

---

## 2. Frontend Changes

1. **`frontend/src/users/AddAdminModal.tsx`**:
   - Added `isValidMobile` and `normalizeMobile` helper functions.
   - Updated validation error message: `"Enter a valid UAE mobile number (e.g. 50 123 4567 or 050 123 4567)."`.
   - Updated input attributes: `placeholder="e.g. 50 123 4567 or 050 123 4567"`, `maxLength={16}`, allowing spaces, hyphens, and `+`.
   - Normalizes phone numbers in the submission payload.

2. **`frontend/src/dashboard/StaffManagement.tsx`**:
   - Expanded `isSupportedMobile` to accept UAE numbers with `05` prefix, `+971`, and `971`.
   - Updated placeholder to `"e.g. 50 123 4567 or 050 123 4567"`, with `maxLength={16}` for both Create and Edit modals.
   - Normalizes phone numbers prior to dispatching `POST /api/staff` and `PATCH /api/staff/:id`.

3. **`frontend/src/users/Listusers.tsx`**:
   - Replaced strict Indian regex check with `isSupportedMobile` and `normalizeMobile`.
   - Updated input placeholder and dynamic validity indicator.

---

## 3. Backend Changes

1. **`backend/src/schemas/staff.schema.ts`**:
   - Replaced `/^[6-9][0-9]{9}$/` with a Zod transform utilizing `normalizeUaeMobile` and `normalizeIndianMobile`.
   - Returns clear error: `"Phone must be a valid UAE mobile number (e.g. 50 123 4567 or 050 123 4567) or 10-digit Indian mobile number"`.

2. **`backend/src/controllers/admin.controller.ts`**:
   - `createAdminUser` & `updateUser` now validate and normalize phone numbers using `normalizeUaeMobile(phone) ?? normalizeIndianMobile(phone)` before checking uniqueness and persisting to the database.

---

## 4. Customer Account Creation Duplicate & Role Restriction Validation

### Background & Issue
During customer signup (`mode === "register"` in `CustomerAuthModal`), entering an already registered email or phone number previously invoked a silent anti-enumeration "decoy" pattern (`isDecoy = Boolean(existing)`). This returned `200 OK` to the frontend without dispatching an OTP email, trapping the user on the "VERIFY OTP" screen with an "Invalid verification code" error. Furthermore, entering an admin or staff email (such as `kidonusuae@gmail.com`) did not trigger the "Access Restricted" modal screen that existed in the sign-in flow.

### Implementation Details

1. **`backend/src/controllers/auth.controller.ts`**:
   - **`customerSignupRequestOtp`**:
     - Pre-checks `existingUsers` matching either the normalized email or submitted UAE phone variants (`submittedPhone`, `0...`, `971...`, `+971...`).
     - If any matching user has an administrative or staff profile (`role !== "CUSTOMER"`), responds immediately with HTTP 403 `code: "ROLE_RESTRICTED"`.
     - If the email is already registered, responds with HTTP 409 `code: "EMAIL_ALREADY_EXISTS"` and a prompt to sign in instead.
     - If the mobile number is already registered, responds with HTTP 409 `code: "PHONE_ALREADY_EXISTS"`.
     - If both match, responds with HTTP 409 `code: "EMAIL_AND_PHONE_ALREADY_EXISTS"`.
     - Enqueues genuine OTP verification challenge with `isDecoy: false` so that legitimate new signups reliably receive OTP emails.
   - **`customerSignupVerifyOtp`**:
     - Added defense-in-depth check for role restrictions (`ROLE_RESTRICTED`) and phone format variants before creating the user document.

2. **`frontend/src/components/CustomerAuthModal.tsx`**:
   - Added handling for `EMAIL_ALREADY_EXISTS`, `PHONE_ALREADY_EXISTS`, `EMAIL_AND_PHONE_ALREADY_EXISTS`, and `SIGNUP_CONFLICT`.
   - Populates inline validation errors (`setEmailError`, `setPhoneError`) and emits toast notifications advising the customer to sign in.
   - Preserves `ROLE_RESTRICTED` handling which instantly transitions to the "Access Restricted" modal screen with "Try a different email".
   - Clears `emailError` and `phoneError` dynamically as soon as the user modifies the inputs.
