name := "vault5431"

version := "0.2"

isSnapshot := true

lazy val vault5431 = project.in(file("."))

libraryDependencies ++= Seq(
  "commons-io"            % "commons-io"        % "2.4",
  "commons-validator"     % "commons-validator" % "1.5.0",
  "com.google.code.gson"  % "gson"              % "2.6.2",
  "com.sparkjava"         % "spark-core"        % "2.3",
  "com.twilio.sdk"        % "twilio-java-sdk"   % "5.9.0",
  "org.apache.commons"    % "commons-csv"       % "1.2",
  "org.freemarker"        % "freemarker"        % "2.3.23",
  "junit"                 % "junit"             % "4.12" % Test,
  "com.novocode"          % "junit-interface"   % "0.11" % Test
)

initialize := {
  val required = "1.8"
  val current = sys.props("java.specification.version")
  assert(current == required, s"Unsupported JDK: java.specification.version $current != $required")
}

unmanagedBase := baseDirectory.value / "lib"

mainClass in assembly := Some("vault5431.Vault")

test in assembly := {}
