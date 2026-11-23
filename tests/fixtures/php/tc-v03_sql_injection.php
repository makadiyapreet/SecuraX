<?php
function find_product($id) {
    global $db;
    $sql = "SELECT * FROM products WHERE id = " . $id;
    return mysqli_query($db, $sql);
}
?>