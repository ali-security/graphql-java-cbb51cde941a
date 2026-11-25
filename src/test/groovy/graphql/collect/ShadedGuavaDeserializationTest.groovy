package graphql.collect

import com.google.common.collect.MapMaker
import spock.lang.Specification

import java.lang.reflect.Field
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReferenceArray

/**
 * Guava is shaded into the graphql-java jar (relocated to graphql.com.google.common), so the
 * Guava version used by the build decides which Guava fixes ship with graphql-java.
 *
 * CVE-2026-102554 (GHSA-xxph-c9ww-hj94): deserializing a MapMakerInternalMap used the size read
 * from the stream as the initial capacity, so a crafted stream could force huge table allocations.
 */
class ShadedGuavaDeserializationTest extends Specification {

    def "deserializing a MapMaker map does not trust the serialized size as its capacity"() {
        given:
        ConcurrentMap<String, String> map = new MapMaker().weakValues().makeMap()
        byte[] bytes = serialize(map)

        when:
        def ois = new ObjectInputStream(new ByteArrayInputStream(bytes)) {
            @Override
            int readInt() throws IOException {
                super.readInt()
                return Integer.MAX_VALUE
            }
        }
        Map<?, ?> deserialized
        try {
            deserialized = (Map<?, ?>) ois.readObject()
        } finally {
            ois.close()
        }

        then:
        // without the fix the tables for 2^30 entries are allocated up front
        notThrown(OutOfMemoryError)
        deserialized.isEmpty()
        // the default concurrency level of 4 spreads the capped capacity of 256 over 4 segments
        firstSegmentTableLength(deserialized) == 64
    }

    def "MapMaker maps larger than the capped capacity still deserialize all their entries"() {
        given:
        ConcurrentMap<Integer, TimeUnit> map = new MapMaker().weakValues().makeMap()
        (0..<1000).each { map.put(it, TimeUnit.SECONDS) }

        when:
        def ois = new ObjectInputStream(new ByteArrayInputStream(serialize(map)))
        Map<?, ?> deserialized
        try {
            deserialized = (Map<?, ?>) ois.readObject()
        } finally {
            ois.close()
        }

        then:
        deserialized.size() == 1000
        (0..<1000).every { deserialized.get(it) == TimeUnit.SECONDS }
    }

    private static byte[] serialize(Object object) {
        def baos = new ByteArrayOutputStream()
        def oos = new ObjectOutputStream(baos)
        try {
            oos.writeObject(object)
        } finally {
            oos.close()
        }
        return baos.toByteArray()
    }

    // Map instances turn Groovy property access into get(key), so read the internals by reflection
    private static int firstSegmentTableLength(Map<?, ?> map) {
        Object[] segments = (Object[]) field(map.getClass(), "segments").get(map)
        def table = (AtomicReferenceArray<?>) field(segments[0].getClass(), "table").get(segments[0])
        return table.length()
    }

    private static Field field(Class<?> type, String name) {
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name)
                f.setAccessible(true)
                return f
            } catch (NoSuchFieldException ignored) {
                // keep looking in the superclass
            }
        }
        throw new NoSuchFieldException(name)
    }
}
