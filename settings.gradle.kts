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
includeBuild("experimental/secp256k1-kmp") {
    dependencySubstitution {
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp")).using(project(":"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm")).using(project(":jni:jvm:all"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux")).using(project(":jni:jvm:linux"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin")).using(project(":jni:jvm:darwin"))
        substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw")).using(project(":jni:jvm:mingw"))
    }
}
