import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import java.io.Reader;

class DeserializationFixture {
    Object vulnerable(Reader input) {
        XStream stream = new XStream();
        return stream.fromXML(input);
    }

    Object hardened(Reader input, Object policy) {
        XStream stream = createXStream(policy);
        return stream.fromXML(input);
    }

    XStream createXStream() {
        return new XStream();
    }

    XStream createXStream(Object policy) {
        XStream stream = new XStream();
        stream.addPermission(NoTypePermission.NONE);
        return stream;
    }
}
