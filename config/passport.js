const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");

const Staff = require("../entities/staff.entity");
const Restaurant = require("../entities/restaurant.entity");
const { verifyOAuthState, PLATFORM_SCOPE, STAFF_SCOPE } = require("../utils/jwt");

const LOG_PREFIX = "[passport][google-oauth]";
const log = (event, details = {}) => console.info(`${LOG_PREFIX} ${event}`, details);
const warn = (event, details = {}) => console.warn(`${LOG_PREFIX} ${event}`, details);

/**
 * PLATFORM_ADMIN_EMAIL works straight from the environment: the first time that
 * Google account signs in to the platform console, its SUPER_ADMIN row is
 * created here, so a deployment does not depend on the seed having run. The
 * seed still creates it ahead of time when it does run.
 */
const envPlatformAdminEmail = () =>
  String(process.env.PLATFORM_ADMIN_EMAIL || "").toLowerCase().trim();

async function createEnvPlatformAdmin(email, profile) {
  const envName = process.env.PLATFORM_ADMIN_NAME || profile.displayName || "Platform Admin";
  log("platform-admin.provision.start", {
    source: "env",
    email,
    name: envName,
    envAdminEmailConfigured: Boolean(process.env.PLATFORM_ADMIN_EMAIL),
    envAdminNameConfigured: Boolean(process.env.PLATFORM_ADMIN_NAME),
  });

  try {
    const admin = await Staff.create({
      restaurant: null,
      name: envName,
      email,
      role: "SUPER_ADMIN",
    });
    log("platform-admin.provision.created", {
      source: "database",
      persistedTo: "Staff",
      staffId: String(admin._id),
      email,
      name: envName,
    });
    return admin;
  } catch (err) {
    // Two sign-ins at once: the other one created it first, so use that row.
    if (err?.code === 11000) {
      warn("platform-admin.provision.duplicate", {
        source: "database",
        action: "using existing SUPER_ADMIN row",
        email,
      });
      const admin = await Staff.findOne({ restaurant: null, email, role: "SUPER_ADMIN" });
      log("platform-admin.lookup.complete", {
        source: "database",
        found: Boolean(admin),
        staffId: admin ? String(admin._id) : undefined,
        email,
      });
      return admin;
    }
    throw err;
  }
}

/** First Google sign-in links the Google account to the staff row. */
async function linkGoogle(staff, profile) {
  if (staff.googleId) {
    log("google-account.link.skipped", {
      source: "database",
      staffId: String(staff._id),
      existingGoogleId: staff.googleId,
      reason: "already linked",
    });
    return;
  }

  const googleId = profile.id;
  const avatar = profile.photos?.[0]?.value;
  staff.googleId = googleId;
  staff.avatar = avatar;
  await staff.save();

  log("google-account.linked", {
    source: "google-profile",
    staffId: String(staff._id),
    googleId,
    avatar,
  });
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
        if (!email) {
          warn("callback.rejected", {
            source: "google-profile",
            reason: "no email from Google",
            profileId: profile?.id,
          });
          return done(null, false, { message: "No email from Google" });
        }

        let state;
        try {
          state = verifyOAuthState(req.query.state);
          log("callback.state.verified", {
            source: "jwt-state",
            state,
            rawState: req.query.state,
          });
        } catch (err) {
          warn("callback.rejected", {
            source: "jwt-state",
            reason: "invalid or expired OAuth state",
            error: err?.message,
          });
          return done(null, false, { message: "Login link expired — please try again" });
        }

        const { slug } = state;

        // ── Platform (SUPER_ADMIN) login ──────────────────────────────────────
        if (slug === PLATFORM_SCOPE) {
          log("platform-admin.lookup.start", {
            source: "database",
            email,
            role: "SUPER_ADMIN",
            restaurant: null,
          });

          let admin = await Staff.findOne({ restaurant: null, email, role: "SUPER_ADMIN" });
          log("platform-admin.lookup.complete", {
            source: "database",
            found: Boolean(admin),
            staffId: admin ? String(admin._id) : undefined,
            email,
          });

          const configuredEnvEmail = envPlatformAdminEmail();
          const envEmailMatches = Boolean(configuredEnvEmail && email === configuredEnvEmail);
          log("platform-admin.env-check", {
            source: "env",
            configuredEnvEmail,
            googleEmail: email,
            matchesGoogleAccount: envEmailMatches,
            configuredAdminName: process.env.PLATFORM_ADMIN_NAME || null,
          });

          if (admin) {
            log("platform-admin.source.selection", {
              source: "database",
              reason: "matched Staff row by email and role",
              staffId: String(admin._id),
            });
          } else if (envEmailMatches) {
            log("platform-admin.source.selection", {
              source: "env",
              reason: "no DB row found, but env email matches",
              email,
            });
            admin = await createEnvPlatformAdmin(email, profile);
          } else {
            warn("platform-admin.login.rejected", {
              source: "database+env",
              reason: "no database row and Google account does not match configured env admin",
              email,
              configuredEnvEmail,
            });
          }

          if (!admin) {
            return done(null, false, { message: "Not a platform administrator" });
          }
          if (!admin.isActive) {
            warn("platform-admin.login.rejected", {
              source: "database",
              staffId: String(admin._id),
              reason: "account deactivated",
            });
            return done(null, false, { message: "Account is deactivated" });
          }

          await linkGoogle(admin, profile);
          log("platform-admin.login.accepted", {
            source: "database",
            staffId: String(admin._id),
            restaurant: null,
            slug,
          });
          return done(null, { staff: admin, restaurant: null, slug });
        }

        // ── Shared staff sign-in (/admin) ─────────────────────────────────────
        // No restaurant in the URL: find every restaurant this Google account
        // is active staff at. One -> straight in. Several -> let them choose.
        if (slug === STAFF_SCOPE) {
          log("shared-staff.lookup.start", {
            source: "database",
            email,
            filters: {
              restaurant: { $ne: null },
              isActive: true,
              role: ["ADMIN", "STAFF"],
            },
          });

          const rows = await Staff.find({
            email,
            restaurant: { $ne: null },
            isActive: true,
            role: { $in: ["ADMIN", "STAFF"] },
          }).populate("restaurant");

          const usable = rows.filter((s) => s.restaurant && s.restaurant.status === "active");
          log("shared-staff.lookup.complete", {
            source: "database",
            matchingRows: rows.length,
            usableRows: usable.length,
            restaurantStatuses: rows.map((s) => ({
              staffId: String(s._id),
              restaurant: s.restaurant?.slug,
              restaurantStatus: s.restaurant?.status,
              role: s.role,
            })),
          });

          if (!usable.length) {
            const suspendedOnly = rows.length > 0;
            warn("shared-staff.login.rejected", {
              source: "database",
              reason: suspendedOnly ? "every restaurant is suspended" : "no matching staff rows",
              matchingRows: rows.length,
            });
            return done(null, false, {
              message: suspendedOnly
                ? "Your restaurant is currently suspended"
                : "This Google account is not registered as staff at any restaurant",
            });
          }

          await Promise.all(usable.map((s) => linkGoogle(s, profile)));

          if (usable.length === 1) {
            const [only] = usable;
            log("shared-staff.login.accepted", {
              source: "database",
              staffId: String(only._id),
              restaurantSlug: only.restaurant.slug,
              restaurantName: only.restaurant.name,
            });
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

          log("shared-staff.restaurant-choice.required", {
            source: "database",
            optionsCount: choices.length,
            choices,
          });
          return done(null, { choices, email, slug: STAFF_SCOPE });
        }

        // ── Tenant staff login ────────────────────────────────────────────────
        log("tenant.lookup.start", {
          source: "database",
          restaurantSlug: slug,
        });

        const restaurant = await Restaurant.findOne({ slug });
        if (!restaurant) {
          warn("tenant.login.rejected", {
            source: "database",
            restaurantSlug: slug,
            reason: "restaurant not found",
          });
          return done(null, false, { message: "Restaurant not found" });
        }
        if (restaurant.status !== "active") {
          warn("tenant.login.rejected", {
            source: "database",
            restaurantSlug: slug,
            restaurantStatus: restaurant.status,
            reason: "restaurant suspended",
          });
          return done(null, false, { message: "This restaurant is suspended" });
        }

        // Scoped to this restaurant: the same Google account can be staff at
        // several restaurants, and must only ever match within the one it is
        // logging in to.
        const staff = await Staff.findOne({ restaurant: restaurant._id, email });
        log("tenant.staff-lookup.complete", {
          source: "database",
          found: Boolean(staff),
          restaurantSlug: slug,
          staffId: staff ? String(staff._id) : undefined,
        });

        if (!staff) {
          warn("tenant.login.rejected", {
            source: "database",
            restaurantSlug: slug,
            reason: "no matching staff row in scoped restaurant",
            email,
          });
          return done(null, false, { message: "Access denied: not a registered staff member" });
        }
        if (!staff.isActive) {
          warn("tenant.login.rejected", {
            source: "database",
            restaurantSlug: slug,
            staffId: String(staff._id),
            reason: "account deactivated",
          });
          return done(null, false, { message: "Account is deactivated" });
        }

        if (!staff.googleId) {
          staff.googleId = profile.id;
          staff.avatar = profile.photos?.[0]?.value;
          await staff.save();
          log("tenant.google-account.linked", {
            source: "google-profile",
            staffId: String(staff._id),
            googleId: profile.id,
            restaurantSlug: slug,
          });
        } else {
          log("tenant.google-account.link.skipped", {
            source: "database",
            staffId: String(staff._id),
            existingGoogleId: staff.googleId,
          });
        }

        log("tenant.login.accepted", {
          source: "database",
          restaurantSlug: slug,
          staffId: String(staff._id),
          email,
        });
        return done(null, { staff, restaurant, slug });
      } catch (err) {
        console.error(`${LOG_PREFIX} callback.error`, {
          name: err?.name,
          message: err?.message,
          stack: err?.stack,
        });
        return done(err, null);
      }
    }
  )
);

module.exports = passport;
