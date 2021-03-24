<?php
/**
 *
 * User: huangwalker
 * Date: 2021/3/19
 * Time: 17:50
 * Email: <huangwalker@qq.com>
 */

namespace App\Util\Wx\WxComponent;


class SignUtil
{

    public static function geneSignature($token, $timestamp, $nonce, $encrypt_msg)
    {
        $signature = '';
        //排序
        try {
            $array = [$encrypt_msg, $token, $timestamp, $nonce];
            sort($array, SORT_STRING);
            $str = implode($array);
            $signature = sha1($str);
            return $signature;
        } catch (\Exception $e) {
            return $signature;
        }
    }

    public static function checkSignature($msg_signature, $timestamp, $nonce, $encrypt_msg)
    {
        $token = config('wx.component.token');
        $signature = self::geneSignature($token, $timestamp, $nonce, $encrypt_msg);

        return $signature === $msg_signature;
    }
}