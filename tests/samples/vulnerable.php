<?php
// Vulnerable PHP sample

$password = "hardcoded_pass123";

function getUser($id) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    return mysql_query($query);
}

function runCmd($input) {
    system($_POST['cmd']);
    exec($input);
}

function loadPage($page) {
    include($_GET['page']);
}

function hashUserPass($password) {
    return md5($password);
}

function deserializeData($data) {
    return unserialize($_POST['data']);
}

echo $_GET['username'];

header("Location: " . $_GET['redirect']);
