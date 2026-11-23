<?php
function render_welcome($user_name) {
    $safe = htmlspecialchars($user_name, ENT_QUOTES, 'UTF-8');
    echo "<h1>Welcome back, " . $safe . "!</h1>";
}
?>