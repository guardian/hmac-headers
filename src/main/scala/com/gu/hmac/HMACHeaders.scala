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


object HTTP extends Enumeration {
  type Verb = Value
  val GET, POST, PUT, PATCH, HEAD, OPTIONS, DELETE = Value
}

class HMACToken(val value: String)

object HMACToken {
  private val HmacPattern = "HMAC\\s(.+)".r

  def apply(token: String): HMACToken = new HMACToken(token)

  def parseHeader(authorizationHeader: String) =
    authorizationHeader match {
      case HmacPattern(token) => new HMACToken(token)
      case _ => throw new HMACInvalidTokenError(s"Invalid token header, should be of format $HmacPattern")
    }
}

class HMACDate(val value: DateTime)

object HMACDate {
  def apply(dateHeader: String): HMACDate = {
    Try(dateHeader.fromRfc7231String) match {
      case Success(dateTime) => new HMACDate(dateTime)
      case Failure(e) => throw new HMACInvalidDateError("Invalid Date Format: " + e.getMessage)
    }
  }

  def apply(dateTime: DateTime): HMACDate = {
    new HMACDate(dateTime)
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

class HMACContentType(val value: String) {
  override def toString: String = value
}

object HMACContentType {
  def apply(contentTypeHeader: String): HMACContentType = new HMACContentType(contentTypeHeader.toLowerCase)
}

class HMACContentMD5(val value: String) {
  override def toString: String = value
}

object HMACContentMD5 extends LazyLogging {

  private val UTF8Charset = StandardCharsets.UTF_8

  def apply(md5: String): HMACContentMD5 = new HMACContentMD5(md5)

 def apply(content: Option[String]): HMACContentMD5 = {
   val contentMd5 = content match {
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
   new HMACContentMD5(contentMd5)
  }
}

class HMACAdditionalHeaders(val value: String)

object HMACAdditionalHeaders {

  private[hmac] def lowerCaseHeaderNames(h: Seq[(String, String)]): Seq[(String, String)] = h.map {
    case (name: String, value: String) => {
      (name.toLowerCase(), value)
    }
  }

  private[hmac] def concatenateHeadersWithSameName(h: Seq[(String, String)]): Map[String, String] = h.groupBy(_._1).map{
    case (name: String, headers: Seq[(String, String)]) => (name, headers.map(_._2).mkString(","))
  }

  private[hmac] def sortByHeaderName(h: Map[String, String]): Seq[(String, String)] = h.toSeq.sortWith(_._1 < _._1)

  private[hmac] def concatenateAllHeaders(h: Seq[(String, String)]): String = h.map {
    case (name: String, concatenatedValues: String) => {
      s"$name:$concatenatedValues"
    }
  }.mkString("\n")

  private[hmac] def canonicalisedHeaders =
    lowerCaseHeaderNames _ andThen
    concatenateHeadersWithSameName andThen
    sortByHeaderName andThen
    concatenateAllHeaders

  def apply(additionalHeaders: Seq[(String, String)]): HMACAdditionalHeaders = {
    new HMACAdditionalHeaders(canonicalisedHeaders(additionalHeaders))
  }

  implicit class AdditionalHeadersStrOps(additionalHeadersOpt: Option[HMACAdditionalHeaders]) {
    def toStringValue: String = additionalHeadersOpt.map(_.value).getOrElse("")
  }
}

case class HMACRequest(httpVerb: HTTP.Verb,
                       date: HMACDate,
                       uri: URI,
                       additionalHeaders: Option[HMACAdditionalHeaders] = None,
                       contentType: Option[HMACContentType] = None,
                       contentMd5: Option[HMACContentMD5] = None) {
  import HMACDate.DateTimeOps

  override def toString = {
    val values: Seq[String] = Seq(
      httpVerb.toString,
      contentMd5.toString,
      contentType.toString,
      date.value.toRfc7231String,
      uri.getPath,
      additionalHeaders.toStringValue
    )
    values.mkString("\n")
  }
}

case class HMACHeaderValues(date: String, token: String)

trait HMACHeaders extends LazyLogging {
  import HMACDate.DateTimeOps

  def secret: String

  private val Algorithm = "HmacSHA256"
  private val HmacValidDurationInMinutes = 5
  private val MinuteInMilliseconds = 60000
  private val UTF8Charset = StandardCharsets.UTF_8

  def validateHMACHeaders(
                           httpVerb: HTTP.Verb,
                           date: HMACDate,
                           uri: URI,
                           additionalHeaders: Option[HMACAdditionalHeaders] = None,
                           contentType: Option[HMACContentType] = None,
                           contentMd5: Option[HMACContentMD5] = None
                         )(token: HMACToken): Boolean = {
    val hmacRequest = HMACRequest(
      httpVerb,
      date,
      uri,
      additionalHeaders,
      contentType,
      contentMd5
    )
    logger.debug(s"Validate HMAC request: ${hmacRequest.toString}")
    val dateValid: Boolean = isDateValid(hmacRequest.date)
    val hmacValid: Boolean = isHMACValid(hmacRequest, token)
    logger.debug(s"isDateValid = $dateValid, isHMACValid = $hmacValid")
    dateValid && hmacValid
  }

  def createHMACHeaderValues(httpVerb: HTTP.Verb,
                             uri: URI,
                             additionalHeaders: Option[HMACAdditionalHeaders] = None,
                             contentType: Option[HMACContentType] = None,
                             contentMd5: Option[HMACContentMD5] = None): HMACHeaderValues = {
    val now = DateTime.now()
    val hmacRequest = HMACRequest(
      httpVerb,
      HMACDate(now),
      uri,
      additionalHeaders,
      contentType,
      contentMd5
    )
    createHMACHeaderValues(hmacRequest)
  }

  private[hmac] def createHMACHeaderValues(hmacRequest: HMACRequest): HMACHeaderValues = {
    val hmacValue = sign(hmacRequest)
    HMACHeaderValues(date = hmacRequest.date.value.toRfc7231String, token = hmacValue)
  }

  private[hmac] def isHMACValid(hmacRequest: HMACRequest, token: HMACToken): Boolean = {
    sign(hmacRequest) == token.value
  }

  private[hmac] def isDateValid(date: HMACDate): Boolean  = {
    val now = DateTime.now(DateTimeZone.forID("GMT"))
    val delta = Math.abs(date.value.getMillis - now.getMillis)
    logger.debug(s"Delta is $delta")
    val allowedOffset = HmacValidDurationInMinutes * MinuteInMilliseconds
    logger.debug(s"Allowed offset is $allowedOffset")
    delta <= allowedOffset
  }

  private[hmac] def sign(hmacRequest: HMACRequest) = {
    val toSign = hmacRequest.toString
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
