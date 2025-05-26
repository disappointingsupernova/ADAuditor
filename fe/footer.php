<div class="position-fixed bottom-0 start-0 w-100 text-white d-flex justify-content-between align-items-center px-4 py-2 small" style="background: rgba(0, 0, 0, 0.4); z-index: 10;">
    <div class="text-start">
        &copy; <?= date('Y'); echo " " . $copyright . " " . $application_name; ?>
    </div>
    <div class="text-center">
        Signed in as: <strong><?= htmlspecialchars($displayName) ?></strong> &lt;<span><?= htmlspecialchars($email) ?></span>&gt;
    </div>
    <div class="text-end">
        Support: <a href="mailto:techops@domain.com" class="text-white text-decoration-underline">techops@domain.com</a>
    </div>
</div>
