name := "vault5431"

version := "0.2"

isSnapshot := true

lazy val vault5431 = project.in(file("."))

libraryDependencies ++= Seq(
  "com.sparkjava" % "spark-core" % "2.3",
  "commons-validator" % "commons-validator" % "1.5.0",
  "org.apache.commons" % "commons-csv" % "1.2",
  "org.freemarker" % "freemarker" % "2.3.23",
  "commons-io" % "commons-io" % "2.4",
  "com.google.code.gson" % "gson" % "2.6.2",
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
