import de.johoop.findbugs4sbt.FindBugs._

name := "vault5431"

lazy val vault5431 = project.in(file("."))

findbugsSettings

libraryDependencies ++= Seq(
  "com.sparkjava" % "spark-core" % "2.3",
  "commons-validator" % "commons-validator" % "1.5.0",
  "org.apache.commons" % "commons-csv" % "1.2",
  //  "com.sparkjava" % "spark-template-freemarker" % "2.3",
  "org.freemarker" % "freemarker" % "2.3.23",
  "commons-io" % "commons-io" % "2.4",
  "junit" % "junit" % "4.12" % Test,
  "com.novocode" % "junit-interface" % "0.11" % Test
)

initialize := {
  val required = "1.8"
  val current = sys.props("java.specification.version")
  assert(current == required, s"Unsupported JDK: java.specification.version $current != $required")
}

unmanagedBase := baseDirectory.value / "lib"

mainClass in assembly := Some("vault5431.Vault")
