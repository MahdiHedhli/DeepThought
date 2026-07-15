import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

final class LdapInjectionFixture {
    private final String userFilter = "(uid={0})";

    SearchResult vulnerable(DirContext ctx, String userBase, String username)
            throws NamingException {
        var controls = new SearchControls();
        var filter = userFilter.replace("{0}", username);
        return getSingleResult(ctx, userBase, filter, controls);
    }

    SearchResult patched(DirContext ctx, String userBase, String username)
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
        var encoded = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            switch (value.charAt(i)) {
                case '\\' -> encoded.append("\\5c");
                case '*' -> encoded.append("\\2a");
                case '(' -> encoded.append("\\28");
                case ')' -> encoded.append("\\29");
                case '\0' -> encoded.append("\\00");
                default -> encoded.append(value.charAt(i));
            }
        }
        return encoded.toString();
    }
}
