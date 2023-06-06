package com.gu.hmac

import org.apache.commons.codec.binary.Base64
import org.joda.time.format.DateTimeFormat
import org.joda.time.{DateTime, DateTimeZone}

import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Clock
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.control.NoStackTrace
import scala.util.{Failure, Success, Try}

sealed trait HMACError extends NoStackTrace

case class HMACInvalidTokenError(message: String) extends HMACError

case class HMACInvalidDateError(message: String) extends HMACError

case class HMACToken(value: String)


object HMACToken {
  private val HmacPattern = "HMAC\\s(.+)".r

  def get(authorizationHeader: String): HMACToken =
    authorizationHeader match {
      case HmacPattern(token) => HMACToken(token)
      case _ => throw new HMACInvalidTokenError(s"Invalid token header, should be of format $HmacPattern")
    }

  implicit class TokenOps(hmacValue: String) {
    def toHeaderValue: String = s"HMAC $hmacValue"
  }
}

case class HMACDate(value: DateTime)

object HMACDate {
  def get(dateHeader: String): HMACDate = {
    Try(dateHeader.fromRfc7231String) match {
      case Success(dateTime) => HMACDate(dateTime)
      case Failure(e) => throw new HMACInvalidDateError("Invalid Date Format: " + e.getMessage)
    }
  }

  // http://tools.ietf.org/html/rfc7231#section-7.1.1.2
  private val HTTPDateFormat = DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'").withZone(DateTimeZone.forID("GMT"))

  implicit class DateTimeOps(dateTime: DateTime) {
    def toRfc7231String: String =
      dateTime.withZone(DateTimeZone.forID("GMT")).toString(HTTPDateFormat)
  }

  implicit class DateStrOps(date: String) {
    def fromRfc7231String: DateTime = HTTPDateFormat.parseDateTime(date)
  }
}

case class HMACHeaderValues(date: String, token: String)

object HMACSignatory {
  import HMACDate.DateTimeOps

  final val Algorithm = "HmacSHA256"
  final val UTF8Charset = StandardCharsets.UTF_8

  def sign(secretKey: String, date: DateTime, uri: URI): String = {
    val input = List[String](date.toRfc7231String, uri.getPath)
    val toSign = input.mkString("\n")
    calculateHMAC(secretKey, toSign)
  }

  private def calculateHMAC(secretKey: String, toEncode: String): String = {
    val signingKey = new SecretKeySpec(secretKey.getBytes(UTF8Charset), Algorithm)
    val mac = Mac.getInstance(Algorithm)
    mac.init(signingKey)
    val rawHmac = mac.doFinal(toEncode.getBytes(UTF8Charset))
    new String(Base64.encodeBase64(rawHmac), UTF8Charset)
  }
}

trait SystemClock {
  protected val clock: Clock = Clock.systemDefaultZone()
}

trait CreateHMACHeader extends SystemClock {
  import HMACToken.TokenOps
  import HMACDate.DateTimeOps

  def createHMACHeaderValuesWithSecret(secretKey: String, uri: URI): HMACHeaderValues = {
    val now = new DateTime(clock.instant().toEpochMilli())
    val hmacValue = HMACSignatory.sign(secretKey, now, uri)
    HMACHeaderValues(date = now.toRfc7231String, token = hmacValue.toHeaderValue)
  }
}

trait ValidateHMACHeader extends SystemClock {
  final val HmacValidDurationInMinutes = 5
  final val MinuteInMilliseconds = 60000

  def validateHMACHeadersWithSecret(secretKey: String, dateHeader: String, authorizationHeader: String, uri: URI): Boolean = {
    val hmacDate = HMACDate.get(dateHeader)
    val hmacToken = HMACToken.get(authorizationHeader)

    isDateValid(hmacDate) && isHMACValid(secretKey, hmacDate, uri, hmacToken)
  }

  private[hmac] def isHMACValid(secretKey: String, date: HMACDate, uri: URI, hmac: HMACToken): Boolean = {
    HMACSignatory.sign(secretKey, date.value, uri) == hmac.value
  }

  private[hmac] def isDateValid(date: HMACDate): Boolean = {
    val now = new DateTime(clock.instant().toEpochMilli())
    val delta = Math.abs(date.value.getMillis - now.getMillis)
    val allowedOffset = HmacValidDurationInMinutes * MinuteInMilliseconds
    delta <= allowedOffset
  }
}

trait HMACHeaders extends ValidateHMACHeader with CreateHMACHeader {
  def secret: String

  def validateHMACHeaders(dateHeader: String, authorizationHeader: String, uri: URI): Boolean =
    validateHMACHeadersWithSecret(secret, dateHeader, authorizationHeader, uri)

  def createHMACHeaderValues(uri: URI): HMACHeaderValues =
    createHMACHeaderValuesWithSecret(secret, uri)
}


