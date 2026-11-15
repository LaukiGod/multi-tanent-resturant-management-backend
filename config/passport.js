const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");

const Staff = require("../entities/staff.entity");
const Restaurant = require("../entities/restaurant.entity");
const { verifyOAuthState, PLATFORM_SCOPE, STAFF_SCOPE } = require("../utils/jwt");

/**
 * PLATFORM_ADMIN_EMAIL works straight from the environment: the first time that
 * Google account signs in to the platform console, its SUPER_ADMIN row is
 * created here, so a deployment does not depend on the seed having run. The
 * seed still creates it ahead of time when it does run.
 */
const envPlatformAdminEmail = () =>
  String(process.env.PLATFORM_ADMIN_EMAIL || "").toLowerCase().trim();

async function createEnvPlatformAdmin(email, profile) {
  try {
    return await Staff.create({
      restaurant: null,
      name: process.env.PLATFORM_ADMIN_NAME || profile.displayName || "Platform Admin",
      email,
      role: "SUPER_ADMIN",
    });
  } catch (err) {
    // Two sign-ins at once: the other one created it first, so use that row.
    if (err?.code === 11000) {
      return Staff.findOne({ restaurant: null, email, role: "SUPER_ADMIN" });
    }
    throw err;
  }
}

/** First Google sign-in links the Google account to the staff row. */
async function linkGoogle(staff, profile) {
  if (staff.googleId) return;
  staff.googleId = profile.id;
  staff.avatar = profile.photos?.[0]?.value;
  await staff.save();
}

/**
 * Google only permits a fixed list of redirect URIs, so the callback URL stays
 * global (`/api/auth/google/callback`) and the tenant travels in the signed
 * `state` parameter instead. `passReqToCallback` is what lets the verify
 * function read it back.
 */
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
    },
    async (req, _accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase();
        if (!email) return done(null, false, { message: "No email from Google" });

        let state;
        try {
          state = verifyOAuthState(req.query.state);
        } catch {
          return done(null, false, { message: "Login link expired — please try again" });
        }

        const { slug } = state;

        // ── Platform (SUPER_ADMIN) login ──────────────────────────────────────
        if (slug === PLATFORM_SCOPE) {
          let admin = await Staff.findOne({ restaurant: null, email, role: "SUPER_ADMIN" });
          if (!admin && email === envPlatformAdminEmail()) {
            admin = await createEnvPlatformAdmin(email, profile);
          }
          if (!admin) {
            return done(null, false, { message: "Not a platform administrator" });
          }
          if (!admin.isActive) return done(null, false, { message: "Account is deactivated" });

          await linkGoogle(admin, profile);
          return done(null, { staff: admin, restaurant: null, slug });
        }

        // ── Shared staff sign-in (/admin) ─────────────────────────────────────
        // No restaurant in the URL: find every restaurant this Google account
        // is active staff at. One -> straight in. Several -> let them choose.
        if (slug === STAFF_SCOPE) {
          const rows = await Staff.find({
            email,
            restaurant: { $ne: null },
            isActive: true,
            role: { $in: ["ADMIN", "STAFF"] },
          }).populate("restaurant");

          const usable = rows.filter((s) => s.restaurant && s.restaurant.status === "active");
          if (!usable.length) {
            const suspendedOnly = rows.length > 0;
            return done(null, false, {
              message: suspendedOnly
                ? "Your restaurant is currently suspended"
                : "This Google account is not registered as staff at any restaurant",
            });
          }

          await Promise.all(usable.map((s) => linkGoogle(s, profile)));

          if (usable.length === 1) {
            const [only] = usable;
            return done(null, { staff: only, restaurant: only.restaurant, slug: only.restaurant.slug });
          }

          const choices = usable
            .map((s) => ({
              staffId: String(s._id),
              slug: s.restaurant.slug,
              name: s.restaurant.name,
              role: s.role,
            }))
            .sort((a, b) => a.name.localeCompare(b.name));
          return done(null, { choices, email, slug: STAFF_SCOPE });
        }

        // ── Tenant staff login ────────────────────────────────────────────────
        const restaurant = await Restaurant.findOne({ slug });
        if (!restaurant) return done(null, false, { message: "Restaurant not found" });
        if (restaurant.status !== "active") {
          return done(null, false, { message: "This restaurant is suspended" });
        }

        // Scoped to this restaurant: the same Google account can be staff at
        // several restaurants, and must only ever match within the one it is
        // logging in to.
        const staff = await Staff.findOne({ restaurant: restaurant._id, email });
        if (!staff) {
          return done(null, false, { message: "Access denied: not a registered staff member" });
        }
        if (!staff.isActive) return done(null, false, { message: "Account is deactivated" });

        if (!staff.googleId) {
          staff.googleId = profile.id;
          staff.avatar = profile.photos?.[0]?.value;
          await staff.save();
        }

        return done(null, { staff, restaurant, slug });
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

module.exports = passport;
