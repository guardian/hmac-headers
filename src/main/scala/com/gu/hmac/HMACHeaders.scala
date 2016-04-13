package com.gu.hmac

import java.net.URI
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.typesafe.scalalogging.LazyLogging
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.digest.DigestUtils
import org.joda.time.format.DateTimeFormat
import org.joda.time.{DateTime, DateTimeZone}

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

trait HMACHeaders extends LazyLogging {
  import HMACDate.DateTimeOps
  import HMACToken.TokenOps

  def secret: String

  private val Algorithm = "HmacSHA256"
  private val HmacValidDurationInMinutes = 5
  private val MinuteInMilliseconds = 60000
  private val UTF8Charset = StandardCharsets.UTF_8

  def validateHMACHeaders(dateHeader: String, authorizationHeader: String, uri: URI): Boolean = {
    val hmacDate = HMACDate.get(dateHeader)
    val hmacToken = HMACToken.get(authorizationHeader)
    logger.debug(s"Validate HMAC headers: dateHeader = $dateHeader, authorizationHeader = $authorizationHeader")
    val dateValid: Boolean = isDateValid(hmacDate)
    val hmacValid: Boolean = isHMACValid(hmacDate, uri, hmacToken)
    logger.debug(s"isDateValid = $dateValid, isHMACValid = $hmacValid")
    dateValid && hmacValid
  }

  def createHMACHeaderValues(uri: URI): HMACHeaderValues = {
    val now = DateTime.now()
    createHMACHeaderValues(uri, now)
  }

  private[hmac] def md5(content: Option[String]): String = {
    content match {
      case Some(c) => {
        logger.debug(s"Creating signature for: $content")
        val digest = DigestUtils.md5(c)
        val base64md5 = new String(Base64.encodeBase64(digest), UTF8Charset)
        logger.debug(s"Base64 encoded MD5 is $base64md5")
        base64md5
      }
      case None => {
        logger.debug("Empty content; returning empty string")
        ""
      }
    }
  }

  private[hmac] def createHMACHeaderValues(uri: URI, now: DateTime): HMACHeaderValues = {
    val hmacValue = sign(now, uri)
    HMACHeaderValues(date = now.toRfc7231String, token = hmacValue.toHeaderValue)
  }

  private[hmac] def isHMACValid(date: HMACDate, uri: URI, hmac: HMACToken): Boolean = {
    sign(date.value, uri) == hmac.value
  }

  private[hmac] def isDateValid(date: HMACDate): Boolean  = {
    val now = DateTime.now(DateTimeZone.forID("GMT"))
    val delta = Math.abs(date.value.getMillis - now.getMillis)
    logger.debug(s"Delta is $delta")
    val allowedOffset = HmacValidDurationInMinutes * MinuteInMilliseconds
    logger.debug(s"Allowed offset is $allowedOffset")
    delta <= allowedOffset
  }

  private[hmac] def sign(date: DateTime, uri: URI): String = {
    val input = List[String](date.toRfc7231String, uri.getPath)
    val toSign = input.mkString("\n")
    logger.debug(s"Creating signature for: $toSign")
    val hmacSignature = calculateHMAC(toSign)
    logger.debug(s"HMAC signature is $hmacSignature")
    hmacSignature
  }

  private[hmac] def calculateHMAC(toEncode: String): String = {
    val signingKey = new SecretKeySpec(secret.getBytes(UTF8Charset), Algorithm)
    val mac = Mac.getInstance(Algorithm)
    mac.init(signingKey)
    val rawHmac = mac.doFinal(toEncode.getBytes(UTF8Charset))
    new String(Base64.encodeBase64(rawHmac), UTF8Charset)
  }

}
