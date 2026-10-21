// SPDX-License-Identifier: GPL-3.0-only

package io.otfabric.conformance

import java.nio.file.Paths

import scala.util.control.NonFatal

import io.stepfunc.dnp3c.conformance.{ Harness, Revisions }
import io.stepfunc.dnp3c.conformance.api.{ HarnessExecutionException, Options, ProcedureOutcome, TestElement }

/**
 * Runs every procedure of a revision against the conformance outstation, each on its own, so that a failure doesn't
 * stop the run, then writes the report.
 *
 * Usage: Run <revision> <device.ini> [control host:port] [procedure or section ...]
 */
object Run {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      System.err.println("usage: Run <revision> <device.ini> [host:port] [procedure or section ...]")
      sys.exit(2)
    }
    val revision = Revisions.find(args(0)).getOrElse {
      System.err.println(s"unknown revision ${args(0)}")
      sys.exit(2)
    }
    val options = Options.load(Paths.get(args(1)))
    val (host, port) = args.lift(2).map(_.split(':')) match {
      case Some(Array(h, p)) => (h, p.toInt)
      case _ => ("127.0.0.1", 20099)
    }
    val selected = args.drop(3).toList match {
      case Nil => List("all")
      case ids => ids
    }
    val harness = new Harness(options, new Plugin(host, port), revision)

    def leaves(e: TestElement): List[String] =
      if (e.subElements.isEmpty) List(e.id) else e.subElements.toList.flatMap(leaves)

    val ids = selected.flatMap(id => leaves(revision.elements(id))).distinct
    var failed = 0
    var excluded = 0
    var warned = 0
    for (id <- ids) {
      val line =
        try {
          val summary = harness.run(id)
          summary.results
            .map { r =>
              r.outcome match {
                case ProcedureOutcome.Failed(msg) =>
                  failed += 1
                  s"FAIL $id: $msg"
                case ProcedureOutcome.Excluded(reason) =>
                  excluded += 1
                  s"EXCLUDED $id: $reason"
                case ProcedureOutcome.Skipped(reason) => s"SKIP $id: $reason"
                case ProcedureOutcome.Passed if r.warnings.nonEmpty =>
                  warned += 1
                  s"WARN $id: ${r.warnings.mkString("; ")}"
                case ProcedureOutcome.Passed => s"PASS $id"
              }
            }
            .mkString("\n")
        } catch {
          case e: HarnessExecutionException =>
            failed += 1
            s"FAIL $id: harness: ${e.getMessage}"
          case NonFatal(e) =>
            failed += 1
            s"FAIL $id: ${e.getClass.getSimpleName}: ${e.getMessage}"
        }
      println(line)
    }
    val reported =
      try {
        println(s"report: ${harness.writeReport()}")
        true
      } catch {
        case NonFatal(e) =>
          System.err.println(s"Failed to write the report: ${e.getMessage}")
          false
      }
    println(s"${ids.size} procedures, $failed failed, $excluded excluded, $warned passed with warnings")
    if (failed > 0 || excluded > 0 || !reported) sys.exit(1)
  }
}
