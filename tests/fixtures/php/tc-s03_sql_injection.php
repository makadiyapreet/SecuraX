<?php
function find_product($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id");
    $stmt->execute(['id' => (int)$id]);
    return $stmt->fetch();
}
?>