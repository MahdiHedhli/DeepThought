// XXE (CWE-611) fixture: a VULNERABLE and a HARDENED XML-parser factory in one file,
// modeled on the seed (Apache Tika CVE-2025-66516). The detector only parses this.
import javax.xml.stream.XMLInputFactory;
import javax.xml.parsers.DocumentBuilderFactory;

public class XxeFixture {
    // VULNERABLE: an XMLInputFactory used on untrusted XML with DTDs/external entities
    // left enabled (namespace/validating flags are not XXE hardening).
    public static XMLInputFactory vulnerableFactory() {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true);
        factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
        return factory;
    }

    // HARDENED: the same factory with DTDs and external entities disabled.
    public static XMLInputFactory safeFactory() {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return factory;
    }
}
