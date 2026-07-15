<?php

class LookupModel {
    public function vulnerableLookup($order_id) {
        return $this->db->query("SELECT * FROM `orders` WHERE `order_id` = " . $order_id);
    }

    public function numericLookup($order_id) {
        return $this->db->query("SELECT * FROM `orders` WHERE `order_id` = " . (int)$order_id);
    }
}

function vulnerableHaving($filter) {
    $sql_having = ' HAVING (';
    $sql_having .= 'name LIKE "%' . $filter . '%"';
    $sql_having .= ')';
    return $sql_having;
}

function quotedHaving($filter) {
    $sql_having = ' HAVING (';
    $sql_having .= 'name LIKE ' . db_qstr('%' . $filter . '%');
    $sql_having .= ')';
    return $sql_having;
}
