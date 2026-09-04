rootProject.name = "bitcoin-kmp"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
    }
}

// Use the local experimental secp256k1-kmp fork (with FROST/ChillDKG support) instead of the
// artifacts published on Maven Central. All artifacts need explicit substitutions: the JNI artifacts
// because the fork's subproject names don't match their published artifact ids, and the root module
// because Gradle's automatic substitution doesn't cover the included build's root project here.
// Mirrors the `skip.android` switch secp256k1-kmp reads from its own local.properties: when it is
// set that build drops :jni:android, so the substitution below has to drop with it.
val includeSecpAndroid = File("$rootDir/experimental/secp256k1-kmp/local.properties")
    .takeIf { it.exists() }
    ?.inputStream()?.use { java.util.Properties().apply { load(it) } }
    ?.run { getProperty("skip.android", "false")?.toBoolean() }
    ?.not()
    ?: true

includeBuild("experimental/secp256k1-kmp") {
    dependencySubstitution {
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp")).using(project(":"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm")).using(project(":jni:jvm:all"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux")).using(project(":jni:jvm:linux"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin")).using(project(":jni:jvm:darwin"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw")).using(project(":jni:jvm:mingw"))
        // Android consumers need this one too, and without it they silently fall back to the stock
        // artifact on Maven Central -- which carries none of the fork's FROST/ChillDKG modules, so the
        // kotlin API resolves but the native call fails with UnsatisfiedLinkError at runtime. Guarded
        // because :jni:android only exists when secp256k1-kmp's own settings.gradle.kts includes it;
        // substituting to a project that is not in the build fails configuration outright.
        if (includeSecpAndroid) {
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-android")).using(project(":jni:android"))
        }
    }
}
