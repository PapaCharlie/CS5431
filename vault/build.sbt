import de.johoop.findbugs4sbt.FindBugs._

name := "vault5431"

lazy val vault5431 = project.in(file("."))

findbugsSettings

libraryDependencies ++= Seq(
  "com.sparkjava" % "spark-core" % "2.3",
  "commons-validator" % "commons-validator" % "1.5.0"
)

initialize := {
  val required = "1.8"
  val current = sys.props("java.specification.version")
  assert(current == required, s"Unsupported JDK: java.specification.version $current != $required")
}

unmanagedBase := baseDirectory.value / "lib"
