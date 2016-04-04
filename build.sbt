import sbtrelease._
import ReleaseTransformations._

name := "hmac-headers"

version := "1.0"

scalaVersion := "2.11.8"

organization := "com.gu"

crossScalaVersions := Seq(scalaVersion.value)

scmInfo := Some(ScmInfo(
  url("https://github.com/guardian/hmac-headers"),
  "scm:git:git@github.com:guardian/hmac-headers.git"
))

homepage := Some(url("https://github.com/guardian/hmac-headers"))

libraryDependencies ++= Seq(
  "joda-time" % "joda-time" % "2.9.3",
  "commons-codec" % "commons-codec" % "1.10",
  "org.joda" % "joda-convert" % "1.8.1",
  "org.scalatest" % "scalatest_2.11" % "2.2.6" % "test"
)

pomExtra := (
  <developers>
    <developer>
      <id>nlindblad</id>
      <name>Niklas Lindblad</name>
      <url>https://github.com/guardian/hmac-headers</url>
    </developer>
    <developer>
      <id>emma-p</id>
      <name>Emmanuelle Poirier</name>
      <url>https://github.com/guardian/hmac-headers</url>
    </developer>
  </developers>)

publishMavenStyle := true
publishArtifact in Test := false
licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0.html"))

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomIncludeRepository := { _ => false }

releaseProcess := Seq[ReleaseStep](
  checkSnapshotDependencies,
  inquireVersions,
  runClean,
  runTest,
  setReleaseVersion,
  commitReleaseVersion,
  tagRelease,
  ReleaseStep(action = Command.process("publishSigned", _)),
  setNextVersion,
  commitNextVersion,
  ReleaseStep(action = Command.process("sonatypeReleaseAll", _)),
  pushChanges
)
