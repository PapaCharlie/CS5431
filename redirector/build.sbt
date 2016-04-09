name := "vault5431-redirector"

version := "0.2"

isSnapshot := true

lazy val vault5431Redirector = project.in(file("."))

libraryDependencies ++= Seq(
  "com.sparkjava" % "spark-core" % "2.3"
)

initialize := {
  val required = "1.8"
  val current = sys.props("java.specification.version")
  assert(current == required, s"Unsupported JDK: java.specification.version $current != $required")
}

mainClass in assembly := Some("vault5431.Redirector")
