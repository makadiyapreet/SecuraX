<?php
function convert_image($filename) {
    $safe = escapeshellarg($filename);
    return shell_exec("convert " . $safe . " output.png");
}
?>