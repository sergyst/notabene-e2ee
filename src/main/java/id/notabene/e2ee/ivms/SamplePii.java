package id.notabene.e2ee.ivms;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * The PII vaspA sends in the demo. Shape follows Notabene's V2 PresentPII
 * example. Edit src/main/resources/sample-pii.json to change it.
 */
@Component
public class SamplePii {

    private final Map<String, Object> template;

    @SuppressWarnings("unchecked")
    public SamplePii(ObjectMapper json) {
        try (InputStream in = new ClassPathResource("sample-pii.json").getInputStream()) {
            this.template = json.readValue(new String(in.readAllBytes(), StandardCharsets.UTF_8), Map.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read sample-pii.json", e);
        }
    }

    /** A defensive copy, so callers can mutate freely. */
    public Map<String, Object> get() {
        return deepCopy(template);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopy(Map<String, Object> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        source.forEach((key, value) -> copy.put(key, copyValue(value)));
        return copy;
    }

    @SuppressWarnings("unchecked")
    private static Object copyValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            return deepCopy((Map<String, Object>) map);
        }
        if (value instanceof java.util.List<?> list) {
            return list.stream().map(SamplePii::copyValue).toList();
        }
        return value;
    }
}
