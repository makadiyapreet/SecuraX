<?php
function convert_image($filename) {
    return shell_exec("convert " . $filename . " output.png");
}
?>