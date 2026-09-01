rootProject.name = "bitcoin-kmp"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
    }
}

// Use the local experimental secp256k1-kmp fork (with FROST/ChillDKG support) instead of the
// artifacts published on Maven Central. The root module (fr.acinq.secp256k1:secp256k1-kmp) is
// substituted automatically; the JNI artifacts need explicit substitutions because the fork's
// subproject names don't match their published artifact ids.
includeBuild("experimental/secp256k1-kmp") {
    dependencySubstitution {
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux")).using(project(":jni:jvm:linux"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin")).using(project(":jni:jvm:darwin"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw")).using(project(":jni:jvm:mingw"))
    }
}
