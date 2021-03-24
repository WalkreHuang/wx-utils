<?php
/**
 *
 * User: huangwalker
 * Date: 2021/3/19
 * Time: 10:21
 * Email: <huangwalker@qq.com>
 */

namespace App\Util\Wx\WxComponent;

use App\Common\LogFile\WxLogFile;
use App\Util\LogUtil;
use Exception;

class WxMsgCryptUtil
{
    private $key;
    private $app_id;

    //一个块有多少位
    private $blockSize = 32;

    /**
     * WxMsgCryptUtil constructor.
     * @param  array  $config legal key:app_id,app_secret,token,aes_key
     */
    public function __construct($config = [])
    {
        $component_config = !empty($config) ? $config : config('wx.component');

        $this->key = base64_decode($component_config['aes_key']."=");
        $this->app_id = $component_config['app_id'];
    }

    public function encrypt($text)
    {
        $encrypt_data = null;
        try {
            $key = $this->key;
            $random = $this->getRandomStr();
            $text = $random.pack('N', strlen($text)).$text.$this->app_id;
            $text = $this->encode($text);
            $iv = substr($key, 0, 16);
            $encrypted = openssl_encrypt($text, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);
            $encrypt_data = base64_encode($encrypted);
        } catch (Exception $e) {
            LogUtil::LogDiyInfo('encrypt error code:'.ErrorCode::$EncryptAESError, WxLogFile::WX_COMPONENT_CRYPT);
        }

        return $encrypt_data;
    }

    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    public function getRandomStr()
    {
        $str = "";
        $str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }

        return $str;
    }

    public function decrypt($encrypted)
    {
        $parse_content = null;
        try {
            $key = $this->key;
            $ciphertext = base64_decode($encrypted, true);
            $iv = substr($key, 0, 16);

            $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);
        } catch (Exception $e) {
            LogUtil::LogDiyInfo('decrypt error code:'.ErrorCode::$DecryptAESError, WxLogFile::WX_COMPONENT_CRYPT);
            return $parse_content;
        }

        try {
            //去除补位字符
            $result = $this->decode($decrypted);
            //去除16位随机字符串,网络字节序和AppId
            if (strlen($result) < 16) {
                return "";
            }
            $content = substr($result, 16, strlen($result));
            $len_list = unpack("N", substr($content, 0, 4));
            $xml_len = $len_list[1];
            $parse_content = substr($content, 4, $xml_len);
            $from_appid = substr($content, $xml_len + 4);
        } catch (Exception $e) {
            LogUtil::LogDiyInfo('decrypt error:'.$e->getMessage(), WxLogFile::WX_COMPONENT_CRYPT);
            return $parse_content;
        }

        if ($from_appid != $this->app_id) {
            LogUtil::LogDiyInfo('decrypt error: appid not match', WxLogFile::WX_COMPONENT_CRYPT);
            return $parse_content;
        }

        return $parse_content;
    }


    /**
     * 对需要加密的明文进行填充补位
     * @param $text  /需要进行填充补位操作的明文
     * @return
     */
    public function encode($text)
    {
        $blockSize = $this->blockSize;
        $text_length = strlen($text);
        //计算需要填充的位数
        $amount_to_pad = $blockSize - ($text_length % $blockSize);
        if ($amount_to_pad == 0) {
            $amount_to_pad = $blockSize;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = "";
        for ($index = 0; $index < $amount_to_pad; $index++) {
            $tmp .= $pad_chr;
        }
        return $text.$tmp;
    }

    /**
     * 对解密后的明文进行补位删除
     * @param /decrypted 解密后的明文
     * @return /删除填充补位后的明文
     */
    public function decode($text)
    {
        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > $this->blockSize) {
            $pad = 0;
        }

        return substr($text, 0, (strlen($text) - $pad));
    }
}