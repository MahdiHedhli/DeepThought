<?php

function vulnerable($ldap, $credentials, $searchString) {
    return $ldap->simple_search(
        str_replace('[search]', $credentials['username'], $searchString)
    );
}

function patched($ldap, $credentials, $searchString) {
    return $ldap->simple_search(
        str_replace(
            '[search]',
            $ldap->escape($credentials['username'], null, LDAP_ESCAPE_FILTER),
            $searchString
        )
    );
}
