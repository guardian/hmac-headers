import ReleaseTransformations.*
import sbtversionpolicy.withsbtrelease.ReleaseVersion

name := "hmac-headers"

scalaVersion := "3.3.4"

organization := "com.gu"

crossScalaVersions := Seq("2.12.20", "2.13.15", scalaVersion.value)

scalacOptions := Seq("-deprecation", "-release:11")

libraryDependencies ++= Seq(
  "joda-time" % "joda-time" % "2.9.3",
  "commons-codec" % "commons-codec" % "1.10",
  "org.joda" % "joda-convert" % "1.8.1",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.4",
  "org.scalatest" %% "scalatest" % "3.2.10" % "test"
)

licenses := Seq(License.Apache2)

Test / testOptions +=
  Tests.Argument(TestFrameworks.ScalaTest, "-u", s"test-results/scala-${scalaVersion.value}", "-o")

// releaseVersion := ReleaseVersion.fromAggregatedAssessedCompatibilityWithLatestRelease().value,
releaseCrossBuild := true // true if you cross-build the project for multiple Scala versions
releaseProcess := Seq[ReleaseStep](
  checkSnapshotDependencies,
  inquireVersions,
  runClean,
  runTest,
  setReleaseVersion,
  commitReleaseVersion,
  tagRelease,
  setNextVersion,
  commitNextVersion
)