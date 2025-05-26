<?php
require 'config.php';
require 'logging.php';
require 'check_auth.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';

$secret = $_GET['token'] ?? null;
$action = $_GET['action'] ?? null;

$userInfo = $_SESSION['saml_user_data'] ?? [];

$firstName = $userInfo['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'][0] ?? '';
$lastName = $userInfo['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'][0] ?? '';
$email = $userInfo['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0] ?? '';
$displayName = trim("$firstName $lastName");

$message = null;
$message_class = 'success';

function send_smtp_notification($to, $subject, $body) {
    global $config;

    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = $config['email']['smtp_server'];
        $mail->Port = $config['email']['smtp_port'];
        $mail->SMTPAuth = !empty($config['email']['smtp_user']);

        if ($mail->SMTPAuth) {
            $mail->Username = $config['email']['smtp_user'];
            $mail->Password = $config['email']['smtp_password'];
        }

        $mail->setFrom(
            $config['email']['from_address'],
            $config['email']['from_name'] ?? $config['email']['from_address']
        );
        $mail->addAddress($to);
        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body    = $body;

        if (isset($config['email']['verify_tls']) && $config['email']['verify_tls'] === false) {
            $mail->SMTPOptions = [
                'ssl' => [
                    'verify_peer'       => false,
                    'verify_peer_name'  => false,
                    'allow_self_signed' => true,
                ]
            ];
        }

        $mail->send();
    } catch (Exception $e) {
        error_log("Failed to send email: " . $mail->ErrorInfo);
        log_action($GLOBALS['pdo'], 'Error', 'Email send failure: ' . $mail->ErrorInfo, $GLOBALS['email']);
    }
}

$show_form = false;
$show_reviews_table = false;
$outstandingReviews = [];

if (!$secret) {
    $stmt = $pdo->prepare("SELECT a.username, a.secret, u.email, CONCAT(u.username, ' (', u.email, ')') AS display_name, a.id, a.audit_date FROM audit_log a LEFT JOIN users u ON a.username = u.username WHERE a.manager_email = ? AND a.date_reviewed IS NULL ORDER BY a.audit_date ASC");
    $stmt->execute([$email]);
    $outstandingReviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($outstandingReviews)) {
        http_response_code(400);
        $message = "You have no outstanding access reviews.";
        $message_class = 'info';
        log_action($pdo, 'Audit', 'No outstanding reviews', $email);
    } else {
        $message = "Please select a user to review:";
        $message_class = 'none';
        $show_reviews_table = true;
        
        log_action($pdo, 'Audit', "Listed " . count($outstandingReviews) . " available reviews", $email);
    }
}

$audit = null;
if ($secret) {
    $stmt = $pdo->prepare("SELECT * FROM audit_log WHERE secret = ?");
    $stmt->execute([$secret]);
    $audit = $stmt->fetch(PDO::FETCH_ASSOC);

    $token_short = substr($secret, 0, 5) . '...' . substr($secret, -5);

    if (!$audit) {
        http_response_code(404);
        $message = "Invalid Token - Audit not found.";
        $message_class = 'warning';
        log_action($pdo, 'Audit', "Tried to open invalid audit token $token_short", $email);
    } else {
        $log_msg = "Opened audit token $token_short for {$audit['username']}";
        log_action($pdo, 'Audit', $log_msg, $email);
    }
}

if ($audit) {
    $username = htmlspecialchars($audit['username']);
    $manager_email = htmlspecialchars($audit['manager_email']);
    $already_reviewed = !empty($audit['date_reviewed']);

    if ($already_reviewed) {
        log_action($pdo, 'Audit', "Opened already reviewed audit for $username", $email);
    }

    if (!$already_reviewed && $_SERVER['REQUEST_METHOD'] !== 'POST') {
        $show_form = true;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $groupsToRemove = $_POST['remove_groups'] ?? [];
    $json = json_encode($groupsToRemove);
    $now = date('Y-m-d H:i:s');

    $update = $pdo->prepare("UPDATE audit_log SET date_reviewed = ?, changes = ? WHERE id = ?");
    $update->execute([$now, $json, $audit['id']]);

    $body = "The following groups were requested for removal for user {$username}:

" . implode("\n", $groupsToRemove);
    send_smtp_notification("techops@sarik.tech", "Access Change Request: $username", $body);

    $message = "The requested changes for <strong>{$username}</strong> have been sent to the TechOps team for actioning.";
    $message_class = 'success';

    $show_form = false;

    log_action($pdo, 'Audit', "Submitted group removal for $username. Groups: $json", $email);

    $stmt = $pdo->prepare("SELECT a.username, a.secret, u.email, CONCAT(u.username, ' (', u.email, ')') AS display_name, a.id, a.audit_date FROM audit_log a LEFT JOIN users u ON a.username = u.username WHERE a.manager_email = ? AND a.date_reviewed IS NULL ORDER BY a.audit_date ASC");
    $stmt->execute([$email]);
    $outstandingReviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (!empty($outstandingReviews)) {
        $show_reviews_table = true;
    }
}

if ($action === 'approve' && isset($audit) && !$already_reviewed) {
    $now = date('Y-m-d H:i:s');
    $update = $pdo->prepare("UPDATE audit_log SET date_reviewed = ? WHERE id = ?");
    $update->execute([$now, $audit['id']]);

    $message = "Existing access for <strong>{$username}</strong> has been approved.";
    $message_class = 'success';
    $show_form = false;

    log_action($pdo, 'Audit', "Access approved for $username", $email);

    // Fetch updated list of outstanding reviews
    $stmt = $pdo->prepare("SELECT a.username, a.secret, u.email, CONCAT(u.username, ' (', u.email, ')') AS display_name, a.id, a.audit_date FROM audit_log a LEFT JOIN users u ON a.username = u.username WHERE a.manager_email = ? AND a.date_reviewed IS NULL ORDER BY a.audit_date ASC");
    $stmt->execute([$email]);
    $outstandingReviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (!empty($outstandingReviews)) {
        $show_reviews_table = true;
    }
}

$groups = [];
if ($audit) {
    $stmt = $pdo->prepare("SELECT group_name FROM user_groups WHERE username = ?");
    $stmt->execute([$audit['username']]);
    $groups = $stmt->fetchAll(PDO::FETCH_COLUMN);
}

if (isset($already_reviewed) && $already_reviewed && !$message) {
    $message = "This access review for <strong>{$username}</strong> has already been completed.";
    $message_class = 'info';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo $application_name;?></title>
    <link rel="icon" type="image/x-icon" href="/radius.ico">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .logo-over-banner { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -60%); z-index: 2; }
        .logo-over-banner svg { height: 60px; max-width: 90vw; }
        .banner-wrapper { position: relative; width: 100%; }
        .text-white {
            text-shadow: 1px 1px 2px #000;
        }
    </style>
</head>
<body class="bg-light pb-5 pt-0">
<div class="position-absolute top-0 start-0 w-100 text-white d-flex justify-content-between align-items-center px-4 py-2" style="background: rgba(0, 0, 0, 0.4); z-index: 10;">
    <div>
        <?php if ($show_reviews_table): ?>
            <a href="/index.php" class="btn btn-outline-light btn-sm" title="View other reviews">All Reviews</a>
        <?php endif; ?>
    </div>
    <div>
        <a href="/logout.php" class="btn btn-outline-light btn-sm">Sign out</a>
    </div>
</div>
<div class="banner-wrapper">
    <img src="/images/banner.png" class="img-fluid w-100" style="max-height: 250px; object-fit: cover;">
    <div class="logo-over-banner text-center">
    <svg viewBox="0 0 158 39" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M51.6537 17.0422C50.9042 16.7918 49.566 16.5413 48.5489 16.5413C47.1303 16.5413 45.6582 16.7361 44.2931 17.1813C44.2931 17.1813 44.3467 17.5152 44.3467 17.6821V36.5189H38.6724V17.8491C38.6724 16.6248 38.2441 14.1763 38.2441 14.1763C41.6434 12.7017 45.2835 11.4774 49.0039 11.4774C50.476 11.4774 52.0819 11.6722 53.3399 12.0061L51.6537 17.0422Z" fill="#FFFFFF"></path>
        <path d="M64.1794 36.5189C59.5409 36.5189 53.3379 34.8313 53.3379 29.2242C53.3379 19.5342 68.3239 22.8549 68.3239 18.6632C68.3239 16.649 65.7164 16.4585 64.2617 16.4585C62.0934 16.4585 59.5683 17.0301 57.5373 17.9011L55.5611 13.5461C58.4156 12.2395 61.9562 11.4774 65.0851 11.4774C70.2726 11.4774 74.1426 13.7366 74.1426 19.2893V31.6194C74.1426 32.6265 74.4719 34.6407 74.4719 34.6407C71.1509 35.6478 67.72 36.5189 64.1794 36.5189ZM68.3513 30.1224V24.2159C66.3751 26.094 59.733 25.3046 59.733 28.7615C59.733 31.2656 62.1483 31.7011 64.2343 31.7011C65.6341 31.7011 67.0887 31.4561 68.4336 31.0206C68.4336 31.0478 68.3513 30.4762 68.3513 30.1224Z" fill="#FFFFFF"></path>
        <path d="M90.437 36.5188C82.9851 36.5188 77.4971 31.2732 77.4971 23.7023C77.4971 17.4292 81.2096 11.6428 88.3655 11.6428C90.168 11.6428 92.0511 12.0754 93.6652 12.9407V1.04346H99.3416V31.5977C99.3416 32.6522 99.6375 34.7883 99.6375 34.7883C96.8935 35.7617 93.3962 36.5188 90.437 36.5188ZM93.6652 30.1646V17.7266C92.6161 16.9154 91.1902 16.591 89.7644 16.591C85.4601 16.591 83.846 20.0249 83.846 23.9727C83.846 28.2448 85.9443 31.5436 90.4908 31.5436C91.5669 31.5436 92.7506 31.4895 93.7459 31.111C93.7728 31.138 93.6652 30.5161 93.6652 30.1646Z" fill="#FFFFFF"></path>
        <path d="M108.145 6.92935C106.172 6.92935 104.664 5.56024 104.664 3.49261C104.664 1.53675 106.172 0 108.145 0C110.091 0 111.708 1.53675 111.708 3.49261C111.736 5.56024 110.091 6.92935 108.145 6.92935ZM105.349 11.9028H111.16V36.5188H105.377V11.9028H105.349Z" fill="#FFFFFF"></path>
        <path d="M126.597 36.5189C121.077 36.5189 116.738 34.5755 116.738 27.8015V11.5052H122.181V26.8576C122.181 29.856 124.004 31.3551 126.674 31.3551C128.214 31.3551 129.806 30.8554 131.244 30.2724C131.244 30.2724 131.167 29.5783 131.167 29.2452V11.4774H136.558V30.6055C136.558 31.7715 136.866 34.0203 136.866 34.0203C133.708 35.2973 129.96 36.5189 126.597 36.5189Z" fill="#FFFFFF"></path>
        <path d="M148.646 36.5189C145.982 36.5189 143.237 35.8384 140.892 34.9402L142.544 30.4218C144.196 31.1567 146.408 31.8644 148.167 31.8644C149.899 31.8644 151.738 31.3473 151.738 29.2242C151.738 24.9508 141.505 26.2573 141.505 18.391C141.505 13.4644 146.488 11.4774 150.192 11.4774C152.67 11.4774 155.175 12.049 156.961 12.92L155.362 17.3839C153.87 16.8123 151.791 16.2679 150.192 16.2679C148.78 16.2679 147.287 16.7035 147.287 18.4183C147.287 22.4467 158 20.623 158 29.3058C158 34.6408 152.937 36.5189 148.646 36.5189Z" fill="#FFFFFF"></path>
        <path d="M15.2352 15.6518C11.8044 15.7359 9.03233 18.7346 9.05977 22.2937V37.4272C10.9261 38.2119 12.9846 38.6322 15.1254 38.6042L15.0156 21.8453L21.1362 20.1078C20.8343 19.0709 20.2853 18.118 19.5168 17.3614C18.3915 16.2123 16.8545 15.6238 15.2352 15.6518Z" fill="#FFFFFF"></path>
        <path d="M15.2923 5.21735C6.80837 5.27158 -0.052072 12.5652 0.000297844 21.5398C0.0264828 26.2305 1.93798 30.4331 4.97543 33.3885V21.9194C4.97543 21.6212 4.97543 21.3229 5.00162 21.0518C5.39439 15.3579 9.92438 10.7486 15.4494 10.5859C18.2512 10.5045 20.922 11.5891 22.9383 13.5955C24.2999 14.9512 25.2425 16.6051 25.7401 18.4489L30.1915 17.1745C28.4371 10.2605 22.4146 5.16312 15.2923 5.21735Z" fill="#FFFFFF"></path>
    </svg>
    </div>
</div>

<div class="container mt-4">
    <div class="card shadow">
        <div class="card-header bg-primary text-white text-center">
            <h4><?php echo $application_name; if ($audit): ?> for <?= $username ?> <?php endif ?></h4>
        </div>
        <div class="card-body">
            <?php if ($message && $message_class !== 'none'): ?>
                <div class="alert alert-<?= htmlspecialchars($message_class) ?> text-center fs-5">
                    <?= $message ?>
                </div>
            <?php elseif ($message_class === 'none'): ?>
                <p class="text-center fs-5"><?= $message ?></p>
            <?php endif; ?>

            <?php if ($show_reviews_table): ?>
                <table class="table table-hover mt-3">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">Username</th>
                            <th scope="col">Email</th>
                            <th scope="col">Review Requested</th>
                            <th scope="col">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($outstandingReviews as $review): ?>
                            <?php
                                $requestedDate = $review['audit_date'];
                                $isOverdue = $requestedDate && (strtotime($requestedDate) < strtotime('-30 days'));
                            ?>
                            <tr class="<?= $isOverdue ? 'table-danger' : '' ?>">
                                <td><?= htmlspecialchars($review['username']) ?></td>
                                <td><?= htmlspecialchars($review['email']) ?></td>
                                <td><?= htmlspecialchars(date('Y-m-d', strtotime($requestedDate))) ?></td>
                                <td><a href="?token=<?= urlencode($review['secret']) ?>" class="btn btn-sm btn-outline-primary">Review</a></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php elseif ($show_form): ?>
                <form method="POST" onsubmit="return selectAll();">
                    <p><strong>Select any groups you wish to remove from <?= $username ?></strong></p>
                    <div class="row">
                        <div class="col-md-5">
                            <label>Current Groups</label>
                            <select id="available" class="form-control" size="8" multiple>
                                <?php foreach ($groups as $group): ?>
                                    <option value="<?= htmlspecialchars($group) ?>"><?= htmlspecialchars($group) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="col-md-2 d-flex flex-column justify-content-center align-items-center">
                            <button type="button" class="btn btn-outline-primary mb-2" onclick="moveSelected('available', 'remove')">→</button>
                            <button type="button" class="btn btn-outline-secondary" onclick="moveSelected('remove', 'available')">←</button>
                        </div>

                        <div class="col-md-5">
                            <label>Groups to be Removed</label>
                            <select id="remove" name="remove_groups[]" class="form-control" size="8" multiple></select>
                        </div>
                    </div>

                    <div class="mt-4 text-end">
                        <button id="action-button" type="submit" class="btn btn-danger">Submit Group Removal Request</button>
                    </div>
                </form>
            <?php endif; ?>

        </div>
    </div>
</div>
<script>
function moveSelected(fromId, toId) {
    const from = document.getElementById(fromId);
    const to = document.getElementById(toId);
    const selected = Array.from(from.selectedOptions);

    selected.forEach(opt => {
        to.add(opt);
    });

    updateActionButton(); 
}

// Select all removal groups before submitting form
function selectAll() {
    const remove = document.getElementById('remove');
    const button = document.getElementById('action-button');

    if (remove.options.length === 0) {
        // Redirect instead of submitting
        window.location.href = window.location.pathname + window.location.search + '&action=approve';
        return false; // Cancel form submission
    }

    for (let i = 0; i < remove.options.length; i++) {
        remove.options[i].selected = true;
    }

    return true; // Allow form submission
}

function updateActionButton() {
    const remove = document.getElementById('remove');
    const button = document.getElementById('action-button');

    if (remove.options.length === 0) {
        button.textContent = 'Accept Current Groups';
        button.classList.remove('btn-danger');
        button.classList.add('btn-success');
    } else {
        button.textContent = 'Submit Group Removal Request';
        button.classList.remove('btn-success');
        button.classList.add('btn-danger');
    }
}

document.getElementById('available').addEventListener('change', updateActionButton);
document.getElementById('remove').addEventListener('change', updateActionButton);

// Also call it once on page load
updateActionButton();

</script>

<?php include 'footer.php'; ?>
</body>
</html>
