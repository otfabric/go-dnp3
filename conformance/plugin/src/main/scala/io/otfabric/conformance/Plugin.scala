// SPDX-License-Identifier: GPL-3.0-only

package io.otfabric.conformance

import java.io.{ BufferedReader, InputStreamReader, OutputStreamWriter, PrintWriter }
import java.net.Socket
import java.nio.charset.StandardCharsets.UTF_8

import io.stepfunc.dnp3c.dnp3._
import io.stepfunc.dnp3c.dnp3.app._
import io.stepfunc.dnp3c.dnp3.app.objects.AttributeValue

/**
 * The integration plugin of the go-dnp3 conformance run. It performs no step itself: each call goes to the
 * conformance outstation (the Go program dut) over its control port, which acts on the outstation or checks what dnp3c
 * parsed against what the outstation holds, and answers with log lines and an error, if any.
 */
final class Plugin(host: String, port: Int) extends IntegrationPlugin {

  private lazy val socket = new Socket(host, port)
  private lazy val out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream, UTF_8), true)
  private lazy val in = new BufferedReader(new InputStreamReader(socket.getInputStream, UTF_8))

  private final case class Reply(index: Int, flags: Option[Int])

  private def call(reporter: PluginReporter, op: String, fields: (String, Json)*): Reply = synchronized {
    out.println(Json.obj(("op" -> Json.Str(op)) +: fields*).render)
    var index = 0
    var flags: Option[Int] = None
    var error: Option[String] = None
    var line = in.readLine()
    while (line != null && line != "end") {
      val (key, value) = line.span(_ != ' ')
      val text = value.drop(1)
      key match {
        case "log" => reporter.log(text)
        case "index" => index = text.toInt
        case "flags" => flags = Some(text.toInt)
        case "error" => error = Some(text)
        case _ => throw new Exception(s"unexpected line from the conformance outstation: $line")
      }
      line = in.readLine()
    }
    if (line == null) throw new Exception("the conformance outstation closed the control connection")
    error.foreach(e => throw new Exception(e))
    Reply(index, flags)
  }

  private def check(reporter: CheckReporter, op: String, fields: (String, Json)*): Option[DeferredCheck] = {
    call(reporter, op, fields*)
    None
  }

  private def kind(k: PointKind): (String, Json) = "kind" -> Json.Str(k.name)
  private def num(name: String, n: Double): (String, Json) = name -> Json.Num(n)
  private def bool(name: String, b: Boolean): (String, Json) = name -> Json.Bool(b)
  private def cls(c: EventClass): (String, Json) = "class" -> Json.Num(c match {
    case EventClass.Class1 => 1
    case EventClass.Class2 => 2
    case EventClass.Class3 => 3
    case _ => 0
  })
  private def expect(e: EventExpectation): (String, Json) = "expect" -> Json.Str(e.toString)
  private def pts(name: String, ps: Seq[GenIndexedPoint[? <: MeasurementPoint]]): (String, Json) =
    name -> Json.Arr(ps.map(p => Plugin.point(p.idx, p.point)))

  override def startProcedure(reporter: PluginReporter): Unit = call(reporter, "startProcedure")
  override def endProcedure(reporter: PluginReporter): Unit = call(reporter, "endProcedure")

  // Actions
  override def cyclePower(reporter: PluginReporter): Unit = call(reporter, "cyclePower")
  override def setLinkLayerConfirm(reporter: PluginReporter, value: Boolean): Unit =
    call(reporter, "setLinkLayerConfirm", bool("bool", value))
  override def setSelfAddressSupport(reporter: PluginReporter, value: Boolean): Unit =
    call(reporter, "setSelfAddressSupport", bool("bool", value))
  override def checkOperate(reporter: CheckReporter, k: OutputKind, index: Int): Option[DeferredCheck] =
    check(reporter, "checkOperate", kind(k), num("index", index))
  override def checkNotOperate(reporter: CheckReporter, k: OutputKind): Option[DeferredCheck] =
    check(reporter, "checkNotOperate", kind(k))
  override def generateInputChanges(reporter: PluginReporter, k: InputKind[?]): Unit =
    call(reporter, "generateInputChanges", kind(k))
  override def generateExactInputEvents(reporter: PluginReporter, k: InputKind[?], numEvents: Int): Unit =
    call(reporter, "generateExactInputEvents", kind(k), num("n", numEvents))
  override def generateClassEvents(reporter: PluginReporter, eventClass: EventClass): Unit =
    call(reporter, "generateClassEvents", cls(eventClass))
  override def generateExactClassEvents(reporter: PluginReporter, eventClass: EventClass, numEvents: Int): Unit =
    call(reporter, "generateExactClassEvents", cls(eventClass), num("n", numEvents))
  override def generatePattern(reporter: PluginReporter, k: InputKind[?]): Unit =
    call(reporter, "generatePattern", kind(k))
  override def uninstall(reporter: PluginReporter, k: PointKind): Unit = call(reporter, "uninstall", kind(k))
  override def reinstallPoints(reporter: PluginReporter): Unit = call(reporter, "reinstallPoints")
  override def enableRemoteSupervisoryControl(reporter: PluginReporter): Unit =
    call(reporter, "enableRemoteSupervisoryControl")
  override def setGlobalRemoteSupervisoryControl(reporter: PluginReporter): Unit =
    call(reporter, "setGlobalRemoteSupervisoryControl")
  override def setIndividualRemoteSupervisoryControl(reporter: PluginReporter, index: Int): Unit =
    call(reporter, "setIndividualRemoteSupervisoryControl", num("index", index))
  override def enableUnsolicitedResponse(reporter: PluginReporter, enabled: Boolean): Unit =
    call(reporter, "enableUnsolicitedResponse", bool("bool", enabled))
  override def setUnsolicitedResponseTimeout(reporter: PluginReporter, timeoutMs: Int): Unit =
    call(reporter, "setUnsolicitedResponseTimeout", num("n", timeoutMs))
  override def setMaxUnsolicitedRetries(reporter: PluginReporter, numRetries: Option[Int]): Unit =
    call(reporter, "setMaxUnsolicitedRetries", numRetries.map(n => num("limit", n)).toSeq*)
  override def setMasterAddress(reporter: PluginReporter, address: Int): Unit =
    call(reporter, "setMasterAddress", num("n", address))
  override def generateUnsolicitedEvents(reporter: PluginReporter, timing: ActionTiming): ActionResult = {
    call(reporter, "generateUnsolicitedEvents")
    ActionResult.Performed
  }
  override def generateNotEnoughUnsolicitedEvents(reporter: PluginReporter): Unit =
    call(reporter, "generateNotEnoughUnsolicitedEvents")
  override def recordCurrentCounterValues(reporter: PluginReporter): Unit =
    call(reporter, "recordCurrentCounterValues")
  override def generateTimeEvent(reporter: PluginReporter): Unit = call(reporter, "generateTimeEvent")
  override def setMaxFragmentSize(reporter: PluginReporter, maxFragmentSize: Int): Unit =
    call(reporter, "setMaxFragmentSize", num("n", maxFragmentSize))
  override def generateMultiFragmentResponse(reporter: PluginReporter): Unit =
    call(reporter, "generateMultiFragmentResponse")
  override def setColdRestartSupport(reporter: PluginReporter, enabled: Boolean): Unit =
    call(reporter, "setColdRestartSupport", bool("bool", enabled))
  override def setAnalogInput(reporter: PluginReporter, index: Int, value: Double): Unit =
    call(reporter, "setAnalogInput", num("index", index), num("value", value))
  override def generateExactFrozenCounterEvents(reporter: PluginReporter, numEvents: Int): Unit =
    call(reporter, "generateExactFrozenCounterEvents", num("n", numEvents))
  override def generateExactSmallAnalogInputEvents(reporter: PluginReporter, numEvents: Int): Unit =
    call(reporter, "generateExactSmallAnalogInputEvents", num("n", numEvents))
  override def generateEventOn(reporter: PluginReporter, k: PointKind, index: Int): Unit =
    call(reporter, "generateEventOn", kind(k), num("index", index))
  override def changeOutputFlag(reporter: PluginReporter, k: PointKind, index: Int, flag: Int): Unit =
    call(reporter, "changeOutputFlag", kind(k), num("index", index), num("flag", flag))
  override def changeBinaryOutputState(reporter: PluginReporter, index: Int): Unit =
    call(reporter, "changeBinaryOutputState", num("index", index))
  override def setAnalogOutputValue(reporter: PluginReporter, index: Int, value: Double): Unit =
    call(reporter, "setAnalogOutputValue", num("index", index), num("value", value))
  override def setFlagsNormal(reporter: PluginReporter, k: PointKind): Unit = call(reporter, "setFlagsNormal", kind(k))
  override def setFlagAbnormal(reporter: PluginReporter, k: PointKind, indices: Seq[Int]): AbnormalFlag = {
    val r = call(reporter, "setFlagAbnormal", kind(k), "indices" -> Json.Arr(indices.map(i => Json.Num(i))))
    AbnormalFlag(r.index, r.flags)
  }

  // Message validations
  override def verifyAllStaticCurrentValues(
      reporter: CheckReporter,
      isClass0: Boolean,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyAllStaticCurrentValues", pts("points", points))
  override def verifyInputCurrentValues[P <: MeasurementPoint](
      reporter: CheckReporter,
      k: InputKind[P],
      points: Seq[GenIndexedPoint[P]]): Option[DeferredCheck] =
    check(reporter, "verifyInputCurrentValues", kind(k), pts("points", points))
  override def verifyRecordedCounterValues(
      reporter: CheckReporter,
      points: Seq[GenIndexedPoint[CounterPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyRecordedCounterValues", pts("points", points))
  override def verifyInputEvents[P <: MeasurementPoint](
      reporter: CheckReporter,
      k: InputKind[P],
      expectation: EventExpectation,
      points: Seq[GenIndexedPoint[P]]): Option[DeferredCheck] =
    check(reporter, "verifyInputEvents", kind(k), expect(expectation), pts("points", points))
  override def verifyFirstInputEvent[P <: MeasurementPoint](
      reporter: CheckReporter,
      k: InputKind[P],
      point: GenIndexedPoint[P]): Option[DeferredCheck] =
    check(reporter, "verifyFirstInputEvent", kind(k), pts("points", List(point)))
  override def verifyClassEvents(
      reporter: CheckReporter,
      eventClass: EventClass,
      expectation: EventExpectation,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyClassEvents", cls(eventClass), expect(expectation), pts("points", points))
  override def verifyFirstClassEvent(
      reporter: CheckReporter,
      eventClass: EventClass,
      point: GenIndexedPoint[MeasurementPoint]): Option[DeferredCheck] =
    check(reporter, "verifyFirstClassEvent", cls(eventClass), pts("points", List(point)))
  override def checkAnalogOutputTolerance(
      reporter: CheckReporter,
      expectedValue: Double,
      actualValue: Double): Option[DeferredCheck] =
    check(reporter, "checkAnalogOutputTolerance", num("expected", expectedValue), num("actual", actualValue))
  override def verifyPolledDataDoNotRepeatUnsolicitedData(
      reporter: CheckReporter,
      unsolicitedResponsePoints: Seq[GenIndexedPoint[MeasurementPoint]],
      polledResponsePoints: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    check(
      reporter,
      "verifyPolledDataDoNotRepeatUnsolicitedData",
      pts("points", unsolicitedResponsePoints),
      pts("points2", polledResponsePoints))
  override def verifyResponseRetainsEvents(
      reporter: CheckReporter,
      previous: Seq[GenIndexedPoint[MeasurementPoint]],
      current: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyResponseRetainsEvents", pts("points", previous), pts("points2", current))
  override def verifyFrozenCounterEvents(
      reporter: CheckReporter,
      points: Seq[GenIndexedPoint[CounterPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyFrozenCounterEvents", pts("points", points))
  override def verifyCommandEventTime(reporter: CheckReporter, sentMs: Long, eventMs: Long): Option[DeferredCheck] =
    check(reporter, "verifyCommandEventTime", num("sentMs", sentMs.toDouble), num("eventMs", eventMs.toDouble))
  override def verifyDelayMeasurementAccuracy(reporter: CheckReporter, delayMs: Long): Option[DeferredCheck] =
    check(reporter, "verifyDelayMeasurementAccuracy", num("delayMs", delayMs.toDouble))
  override def verifyTimestamp(
      reporter: CheckReporter,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    check(reporter, "verifyTimestamp", pts("points", points))
  override def verifyDeviceAttributes(
      reporter: CheckReporter,
      attributes: Seq[(Int, AttributeValue)]): Option[DeferredCheck] =
    check(
      reporter,
      "verifyDeviceAttributes",
      "attrs" -> Json.Arr(attributes.map { case (v, a) =>
        val (t, s) = a match {
          case AttributeValue.VisibleString(x) => ("string", x)
          case other => ("other", other.description)
        }
        Json.obj("v" -> Json.Num(v), "type" -> Json.Str(t), "s" -> Json.Str(s))
      })
    )
}

object Plugin {
  // a point dnp3c parsed, as the conformance outstation reads it
  def point(index: Int, p: MeasurementPoint): Json = {
    val (k, v) = p match {
      case b: BinaryPoint => ("binary input", if (b.value) 1.0 else 0.0)
      case d: DoubleBitPoint => ("double-bit binary input", d.value.value.toDouble)
      case c: CounterPoint => (if (c.isFrozen) "frozen counter" else "counter", c.value.toDouble)
      case a: AnalogPoint => (if (a.isFrozen) "frozen analog input" else "analog input", a.value)
      case b: BinaryOutputStatusPoint => ("binary output status", if (b.value) 1.0 else 0.0)
      case a: AnalogOutputStatusPoint => ("analog output status", a.value)
    }
    val fields = List[(String, Json)]("kind" -> Json.Str(k), "i" -> Json.Num(index), "v" -> Json.Num(v)) ++
      p.flags.map(f => "f" -> Json.Num(f & 0xff)) ++
      p.timestamp.map(t => "t" -> Json.Num(t.value.toDouble)) ++
      p.timestamp.filter(_.isRelative).map(_ => "rel" -> Json.Bool(true)) ++
      Option.when(p.pointType == PointType.Event)("event" -> Json.Bool(true))
    Json.obj(fields*)
  }
}

/** Just enough JSON to write the requests */
sealed trait Json {
  def render: String
}

object Json {
  final case class Str(s: String) extends Json {
    def render: String = {
      val b = new StringBuilder("\"")
      s.foreach {
        case '"' => b ++= "\\\""
        case '\\' => b ++= "\\\\"
        case c if c < ' ' => b ++= f"\\u${c.toInt}%04x"
        case c => b += c
      }
      b += '"'
      b.toString
    }
  }
  final case class Num(n: Double) extends Json {
    def render: String = if (n == math.rint(n) && math.abs(n) < 1e15) n.toLong.toString else n.toString
  }
  final case class Bool(b: Boolean) extends Json {
    def render: String = b.toString
  }
  final case class Arr(items: Seq[Json]) extends Json {
    def render: String = items.map(_.render).mkString("[", ",", "]")
  }
  final case class Obj(fields: Seq[(String, Json)]) extends Json {
    def render: String = fields.map { case (k, v) => Str(k).render + ":" + v.render }.mkString("{", ",", "}")
  }
  def obj(fields: (String, Json)*): Json = Obj(fields)
}
