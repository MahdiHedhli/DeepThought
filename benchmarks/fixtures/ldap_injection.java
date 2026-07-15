import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

final class LdapInjectionFixture {
    SearchResult vulnerable(DirContext ctx, String userBase, String userFilter, String username)
            throws NamingException {
        var controls = new SearchControls();
        var filter = userFilter.replace("{0}", username);
        return getSingleResult(ctx, userBase, filter, controls);
    }

    SearchResult patched(DirContext ctx, String userBase, String userFilter, String username)
            throws NamingException {
        var controls = new SearchControls();
        var filter = userFilter.replace("{0}", escapeLdapFilter(username));
        return getSingleResult(ctx, userBase, filter, controls);
    }

    private SearchResult getSingleResult(
            DirContext ctx, String searchBase, String filter, SearchControls controls)
            throws NamingException {
        return ctx.search(searchBase, filter, controls).next();
    }

    private static String escapeLdapFilter(String value) {
        return value.replace("*", "\\2a");
    }
}
