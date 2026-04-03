<?php
header('Content-Type: application/json');

function get_service_name($port) {
    $services = [
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
        80 => "HTTP", 443 => "HTTPS", 3306 => "MySQL", 3389 => "RDP",
        8080 => "HTTP-Alt"
    ];
    return isset($services[$port]) ? $services[$port] : "Unknown";
}

if (isset($_GET['target']) && isset($_GET['port'])) {
    $target = $_GET['target'];
    $port = intval($_GET['port']);
    $timeout = isset($_GET['timeout']) ? intval($_GET['timeout']) : 1000;
    
    $socket = @fsockopen($target, $port, $errno, $errstr, $timeout / 1000);
    if ($socket) {
        fclose($socket);
        echo json_encode(['open' => true, 'service' => get_service_name($port)]);
    } else {
        echo json_encode(['open' => false, 'service' => null]);
    }
} else {
    echo json_encode(['error' => 'Missing parameters']);
}
?>