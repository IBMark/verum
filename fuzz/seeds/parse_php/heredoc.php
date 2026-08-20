<?php
$sql = <<<SQL
SELECT * FROM users WHERE id = $id
SQL;
$q = <<<'NOW'
literal $notinterpolated
NOW;
?>
trailing html
