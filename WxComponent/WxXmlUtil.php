<?php
/**
 *
 * User: huangwalker
 * Date: 2021/3/19
 * Time: 19:45
 * Email: <huangwalker@qq.com>
 */

namespace App\Util\Wx\WxComponent;

use DOMDocument;

class WxXmlUtil
{
    /**
     * 提取出微信服务器发送给第三方平台自身的通知或事件推送的加密消息
     * @param string $xml_text 待提取的xml字符串
     * @return array
     */
    public static function extractWxServerMsg($xml_text)
    {
        $parse_ret = [];
        libxml_disable_entity_loader(true);

        $xml = new DOMDocument();
        $xml->loadXML($xml_text);
        $encrypt_element = $xml->getElementsByTagName('Encrypt')->item(0);
        $to_user_name_element = $xml->getElementsByTagName('ToUserName')->item(0);
        $app_id_element = $xml->getElementsByTagName('AppId')->item(0);

        $parse_ret['encrypt'] = $encrypt_element->nodeValue ?? '';
        $parse_ret['to_user_name'] = $to_user_name_element->nodeValue ?? '';
        $parse_ret['app_id'] = $app_id_element->nodeValue ?? '';

        return $parse_ret;
    }

    /**
     * 生成xml消息
     * @param string $encrypt 加密后的消息密文
     * @param string $signature 安全签名
     * @param string $timestamp 时间戳
     * @param string $nonce 随机字符串
     */
    public static function generate($encrypt, $signature, $timestamp, $nonce)
    {
        $format = "<xml>
        <Encrypt><![CDATA[%s]]></Encrypt>
        <MsgSignature><![CDATA[%s]]></MsgSignature>
        <TimeStamp>%s</TimeStamp>
        <Nonce><![CDATA[%s]]></Nonce>
        </xml>";
        return sprintf($format, $encrypt, $signature, $timestamp, $nonce);
    }

    /**
     * 提取出第三方平台的 component_verify_ticket
     * @param string $xml_text 待提取的 xml 字符串
     * @return array
     */
    public static function extractComponentTicket($xml_text)
    {
        $parse_ret = [];
        libxml_disable_entity_loader(true);

        $xml = new DOMDocument();
        $xml->loadXML($xml_text);
        $app_id_node = $xml->getElementsByTagName('AppId')->item(0);
        $component_ticket_node = $xml->getElementsByTagName('ComponentVerifyTicket')->item(0);

        $parse_ret['app_id'] = $app_id_node->nodeValue ?? '';
        $parse_ret['component_ticket'] = $component_ticket_node->nodeValue ?? '';
        return $parse_ret;
    }
}