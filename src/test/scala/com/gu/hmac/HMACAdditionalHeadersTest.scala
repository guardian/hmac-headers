package com.gu.hmac

import org.scalatest.{Matchers, FlatSpec}

class HMACAdditionalHeadersTest extends FlatSpec with Matchers {

  "HMACAdditionalHeaders" should "convert each HTTP header name to lowercase" in {
    val headers = Seq(
      ("X-AMZ-acl", "public-read")
    )
    HMACAdditionalHeaders(headers).value should be("x-amz-acl:public-read")
  }

  it should "sort the collection of headers lexicographically by header name" in {
    val headers: Seq[(String, String)] = Seq(
      ("Z-header", "z"),
      ("B-header", "b"),
      ("A-header", "a")
    )
    HMACAdditionalHeaders(headers).value should be("a-header:a\nb-header:b\nz-header:z")

  }

  it should "combine header fields with the same name" in {
    val headers = Seq(
      ("x-amz-meta-username", "fred"),
      ("x-amz-meta-username", "barney")
    )
    HMACAdditionalHeaders(headers).value should be("x-amz-meta-username:fred,barney")
  }

  it should "construct the correct canonicalised header" in {
    val expectedCanonicalisedHeader = "x-amz-acl:public-read\nx-amz-meta-checksumalgorithm:crc32\nx-amz-meta-filechecksum:0x02661779\nx-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net"
    val headers = Seq(
      ("x-amz-acl", "public-read"),
      ("X-Amz-Meta-ReviewedBy", "joe@johnsmith.net"),
      ("X-Amz-Meta-ReviewedBy", "jane@johnsmith.net"),
      ("X-Amz-Meta-FileChecksum", "0x02661779"),
      ("X-Amz-Meta-ChecksumAlgorithm", "crc32")
    )
    HMACAdditionalHeaders(headers).value should be(expectedCanonicalisedHeader)
  }

}
