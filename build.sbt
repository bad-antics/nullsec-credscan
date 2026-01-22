ThisBuild / version := "1.0.0"
ThisBuild / scalaVersion := "3.3.1"
ThisBuild / organization := "com.nullsec"

lazy val root = (project in file("."))
  .settings(
    name := "nullsec-credscan",
    libraryDependencies ++= Seq(
      "org.scalatest" %% "scalatest" % "3.2.17" % Test
    ),
    assembly / mainClass := Some("nullsec.credscan.CredScan"),
    assembly / assemblyJarName := "credscan.jar"
  )
