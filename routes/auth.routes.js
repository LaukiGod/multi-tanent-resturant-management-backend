/**
 * Global auth routes — the parts of the OAuth dance that cannot be per-tenant.
 *
 * Google requires the redirect URI to be registered up front, so there is exactly
 * one callback URL for the whole platform. The tenant is carried in the signed
 * `state` parameter and unpacked by the Google strategy.
 */
const express = require("express");
const router = express.Router();
const passport = require("passport");

const authController = require("../controllers/staffAuth.controller");
const { signOAuthState, PLATFORM_SCOPE, STAFF_SCOPE } = require("../utils/jwt");

// Step 1 (platform): SUPER_ADMIN login — no tenant to resolve.
router.get("/platform/google", (req, res, next) => {
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    state: signOAuthState(PLATFORM_SCOPE),
  })(req, res, next);
});

// Step 1 (shared staff sign-in at /admin): no restaurant yet — it is worked out
// from the Google account in the strategy.
router.get("/staff/google", (req, res, next) => {
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    state: signOAuthState(STAFF_SCOPE),
  })(req, res, next);
});

// Staff at several restaurants: trade the selection ticket for a token at one.
router.post("/staff/select", authController.selectRestaurant);

// Step 2 (everyone): Google redirects here for tenant staff and platform admins alike.
// A failed sign-in goes back to the login page it started from, with the reason.
router.get("/google/callback", (req, res, next) => {
  passport.authenticate("google", { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect(authController.loginFailureUrl(req, info?.message));
    req.user = user;
    return authController.googleCallback(req, res);
  })(req, res, next);
});

router.get("/failed", authController.googleFailure);

module.exports = router;
