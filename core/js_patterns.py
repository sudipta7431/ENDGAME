# core/js_patterns.py
# Advanced JavaScript Logic Intelligence patterns

JS_PATTERNS = {

    # =========================
    # AUTH / ROLE / RBAC
    # =========================
    "admin_check": r"(isAdmin|role\s*===\s*['\"]admin['\"])",
    "superuser_check": r"(isSuperUser|role\s*===\s*['\"]superuser['\"])",
    "staff_check": r"(isStaff|role\s*===\s*['\"]staff['\"])",
    "internal_user": r"(isInternal|user\.internal\s*===\s*true)",
    "rbac_roles": r"(hasRole|checkRole|user\.roles\.includes)",
    "permission_check": r"(hasPermission|canAccess|canExport|canDelete)",
    "access_level": r"(accessLevel\s*[>=<]=?\s*\d+)",

    # =========================
    # AUTHENTICATION STATE
    # =========================
    "authenticated_only": r"(isAuthenticated|loggedIn\s*===\s*true)",
    "session_present": r"(session\.user|auth\.user)",
    "token_present": r"(authToken|accessToken|jwtToken)",
    "refresh_token": r"(refreshToken)",
    "csrf_disabled": r"(disableCsrf|csrf\s*:\s*false)",

    # =========================
    # FEATURE FLAGS / RELEASES
    # =========================
    "feature_flag": r"(featureFlag|enableFeature|toggleFeature)",
    "beta_feature": r"(betaFeature|isBetaUser)",
    "experimental_feature": r"(experimental|labsFeature)",
    "kill_switch": r"(killSwitch|disableFeature)",
    "rollout_percentage": r"(rollout|percentageRollout)",
    "ab_testing": r"(variantA|variantB|abTest)",

    # =========================
    # DEBUG / DEV / ENVIRONMENT
    # =========================
    "debug_flag": r"(DEBUG\s*==\s*true|debug\s*:\s*true)",
    "dev_environment": r"(env\s*===\s*['\"]dev['\"])",
    "staging_environment": r"(env\s*===\s*['\"]staging['\"])",
    "test_mode": r"(testMode\s*===\s*true)",
    "verbose_logging": r"(verbose|enableLogs)",
    "source_maps": r"(sourceMappingURL)",

    # =========================
    # API / BACKEND EXPOSURE
    # =========================
    "internal_api": r"(\/internal\/|internalApi)",
    "admin_api": r"(\/admin\/|adminApi)",
    "legacy_api": r"(legacyApi|deprecatedEndpoint)",
    "api_version": r"(v[0-9]+\/api|api\/v[0-9]+)",
    "hidden_endpoint": r"(hiddenEndpoint|privateApi)",

    # =========================
    # DATA SENSITIVITY
    # =========================
    "export_functionality": r"(exportData|downloadReport|generateReport)",
    "delete_operation": r"(deleteUser|removeAccount|destroy)",
    "mass_assignment": r"(updateAll|bulkUpdate|applyAll)",
    "file_access": r"(filePath|fileName|readFile|writeFile)",
    "config_access": r"(config|getConfig|setConfig)",

    # =========================
    # SECURITY CONTROLS / BYPASS
    # =========================
    "rate_limit_disabled": r"(disableRateLimit|rateLimit\s*:\s*false)",
    "captcha_disabled": r"(disableCaptcha|captcha\s*:\s*false)",
    "2fa_bypass": r"(skip2FA|disable2FA)",
    "security_override": r"(securityOverride|forceAccess)",

    # =========================
    # BUSINESS LOGIC
    # =========================
    "account_status": r"(accountStatus|isSuspended|isActive)",
    "subscription_level": r"(plan\s*===\s*['\"]premium['\"])",
    "payment_gate": r"(hasPaid|paymentStatus\s*===\s*['\"]paid['\"])",
    "trial_user": r"(isTrialUser|trialActive)",
}
