# NEEDLEWORK-ScenarioWriter

# はじめにお読みください
本ツールはMITライセンスです。<br>
ライセンスの内容、および下記注意事項・仕様を確認のうえ、同意いただける場合にのみご利用ください。<br><br>

本ツールは補助ツールとして公開しています。<br>
サポートはベストエフォートとなり、動作を保証するものではないことをあらかじめご了承願います。<br>

また、本ツールにプログラミング上の誤りその他の瑕疵のないこと、<br>
本ツールが特定目的に適合すること並びに本ツール及びその利用が利用者または第三者の権利を侵害するものでないこと、<br>
その他いかなる内容の保証も行うものではありません。本ツールに関して発生するいかなる問題も、利用者の責任及び費用負担により解決されるものとします。<br>

# 本ツールについて
本ツールはファイアウォールのコンフィグファイルから[NEEDLEWORK](https://www.ap-com.co.jp/ja/needlework/)で使用できるcsvを生成するツールです。<br>現在対応しているファイアウォールは以下の通りです。

* Juniper SSG5 <br>
  ※動作確認バージョン：6.3.0r17.0

# ツールの仕様

## protocol
対応しているプロトコルは下記の通りです。<br>
  * ICMP
  * TCP
  * UCP

## IP
* ポリシーのIPがAnyの場合、csvに出力されるIPは下記の通りです。
  * Untrustゾーン：<br>
    8.8.8.8<br>
  * IPアドレスが設定されていないゾーン（トランスペアレントモードのゾーン等）:<br>
   ※「Untrust」の文字列を含んでいるゾーンは送信元IP、宛先IP関係なく「8.8.8.8」を出力します
     * 送信元IP : 4.4.4.4
     * 宛先IP : 6.6.6.6
  * その他のゾーン：<br>
    設定されているルーティングのネットワークアドレスからFW IPを除いた後のアドレス空間が最も広いネットワークの開始および終了IP（ネットワークアドレスとブロードキャストアドレスを除く）<br>
    例：下記のように設定がされている場合、以下の処理が行われます。
    ```
    set route 10.0.0.0/24 interface ethernet0/0 gateway 10.0.0.1
    set route 10.0.0.0/16 interface ethernet0/0 gateway 10.0.0.2
    set interface ethernet0/0 ip 10.0.0.254/24
    set interface bgroup0 ip 172.16.0.254/24
    ```
    `10.0.0.0/16`からFW IPを除いた後のネットワークアドレス
    ```
    [IPv4Network('10.0.128.0/17'), 
    IPv4Network('10.0.64.0/18'),
    IPv4Network('10.0.32.0/19'), 
    IPv4Network('10.0.16.0/20'), 
    IPv4Network('10.0.8.0/21'), 
    IPv4Network('10.0.4.0/22'), 
    IPv4Network('10.0.2.0/23'), 
    IPv4Network('10.0.1.0/24'), 
    IPv4Network('10.0.0.0/25'), 
    IPv4Network('10.0.0.128/26'), 
    IPv4Network('10.0.0.192/27'), 
    IPv4Network('10.0.0.224/28'), 
    IPv4Network('10.0.0.240/29'), 
    IPv4Network('10.0.0.248/30'), 
    IPv4Network('10.0.0.252/31'), 
    IPv4Network('10.0.0.255/32')]
    ```
    `IPv4Network('10.0.128.0/17')`の開始および終了IPである<br>
    `10.0.128.1`, `10.0.255.254`がcsvに出力されます。


## DIP
* dipを範囲で指定した場合、開始IPのみをcsvに出力します。

## VIP
* VIP対応サービス（ポート）は以下の通りです。
  * FTP（21)
  * DNS(53)
  * HTTP(80)
  * NTP(123)
* ポリシーのIPがVIPかつServiceがANYの場合、VIPに設定した全てのIPを出力します。<br>
  例：下記のように設定がされている場合、`192.168.10.1`, `192.168.30.3`, `192.168.80.8`がcsvに出力されます。
  ```
  set interface ethernet0/0 vip interface-ip 21 "FTP" 192.168.10.1
  set interface ethernet0/0 vip interface-ip 53 "DNS" 192.168.30.3
  set interface ethernet0/0 vip interface-ip 123 "NTP" 192.168.80.8
  set policy id 98 name "vip" from "Trust" to "Untrust" "Any" "VIP(ethernet0/0)" "ANY" permit
  ```

## Service
* serviceのポートを範囲設定した場合、終了ポートのみを出力します。<br>
（範囲指定した全ポートを出力しません） <br>
  例： <br>
  `ポート：1000-2000`の場合、`2000`を出力<br>
  ※送信元ポート、宛先ポートともに同じ仕様です<br>
  　　  
* デフォルトで登録されている下記サービスの宛先ポートは以下の通りです。<br>
  下記以外のサービスには対応していません。<br>
  
  * PING(ICMP)
  * ICMP-ANY(ICMP)
  * FTP(UDP 21)
  * SSH(TCP 22)
  * TELNET(TCP 23)
  * SMTP(TCP 25)
  * MAIL(TCP 25)
  * DNS(TCP,UDP 53)
  * TFTP(TCP 69) 
  * HTTP(TCP 80)
  * POP3(TCP 110)   
  * NTP(TCP,UDP 123)
  * MS-RPC-EPM(TCP,UDP 135)
  * NBNAME(UDP 137)
  * NBDS(UDP 138)
  * SMB(TCP 139)
  * IMAP(TCP 143)
  * SNMP(TCP,UDP 161)
  * LDAP(TCP 389)
  * HTTPS(TCP 443)
  * IKE(UDP 500)
  * SYSLOG(UDP 514)
  * TALK(UDP 517)
  * MS-SQL(TCP 1433)
  * WINFRAME(TCP 1494)
  * L2TP(UDP 1701)
  * H.323(TCP 1720)
  * PPTP(TCP 1723)
  * RADIUS(UDP 1812)
  * SIP(TCP, udp 5060)
  * X-WINDOWS(TCP 6000)
  * HTTP-EXT(TCP 8000)
  * TRACEROUTE(icmp, udp 33400)
  * TCP-ANY(TCP 65535)
  * UDP-ANY(UDP 65535)
* ポリシーのServiceがANYの場合、csvに出力される宛先ポート番号は下記の通りです。
  * ICMP:なし
  * TCP,UDP:65535

## ゾーン
* ゾーンにIPアドレスが設定されていない場合（トランスペアレントモード等）、 シナリオCSVの「FW IP」にはIPアドレスではなくゾーン名が出力されます。

## マルチセルポリシー
`※マルチセルポリシー`：1つのポリシーに複数のIPアドレス、サービスを設定しているポリシー
* マルチセルポリシーは1行目のポリシーをベースにテストシナリオを作成します。<br>
  （全てのパターンでは作成しません）
  ```
  ポリシー例：
  set policy id 1 from "Trust" to "Untrust"  "192.168.1.100/32" "10.1.255.10/32" "HTTP" permit log 
  set policy id 1
  set src-address "192.168.255.100/32"
  set service "HTTPS"
  exit
  ```
  上記ポリシーの場合、下記がベースポリシーになります。<br>
  ```
  送信元IP：192.168.1.100、宛先IP：10.1.255.10、サービス：HTTP（TCP 80）
  ```
  送信元IPアドレス（set src-address "192.168.255.100/32"）がマルチセルポリシーの要素として定義されているので、<br>
  ベースポリシーの送信元IPを変更したテストシナリオを作成します。<br>
  ```
  送信元IP（★変更箇所）：192.168.255.100、宛先IP：10.1.255.10、サービス：HTTP（TCP 80）
  ```
  サービス（set service "HTTPS"）もマルチセルポリシーの要素として定義されているため、ベースポリシーのサービスを変更したテストシナリオを作成します。
  ```
  送信元IP：192.168.1.100、宛先IP：10.1.255.10、サービス（★変更箇所）：HTTPS（TCP 443）
  ```
  上記ポリシーでは、ベースシナリオの他に2つのシナリオが出力されます。<br>
  ※ベースポリシーから出力したテストシナリオをベースシナリオと記述<br>

## その他
* アドレス名またはサービス名にスペースが含まれる場合、正常にcsvが出力されない可能性がありますのでご注意ください。
* csvに非出力のポリシーは理由がメッセージとして出力されます。

## エラー
出力されるエラーは以下の通りです。<br>

* `有効化していないポリシーの出力オプションが入力されていません 有効化していないポリシーは出力しません`<br>
  ツール実行時にオプションで`n`を指定した場合、およびオプションを指定しない場合に出力されます。<br>
  （無効になっているポリシーのシナリオ出力をスキップします）

* `policy id = xx は{宛先 or 送信元}IPが登録されていないため出力されませんでした`<br>
  ポリシーに設定されているアドレスオブジェクトにIPアドレスが設定されていない場合に出力されます。（シナリオ出力をスキップします）
  
* `{tcp or udp or icmp}の{サービス名}は対応していないサービスです 出力をスキップしました`<br>
  対応していないサービスを含んでいる場合に出力されます。（シナリオ出力をスキップします）

* `前のポリシーで出力しているためpolicy_id = {ポリシーID}では{tcp or udp or icmp}のポリシーの出力をスキップします`<br>
  内容が重複しているポリシーがある場合に出力されます。（シナリオ出力をスキップします）

# ツールの使用方法
本ツールはの利用方法は以下の通りです。<br>

## 動作環境

* OS : Windows 10(64bit)

## 事前準備

1. 下記URLよりzipファイルをダウンロードします。<br>
   ※最新バージョンをご利用ください<br>
    https://github.com/ap-communications/NEEDLEWORK-ScenarioWriter/releases
2. ダウンロードしたzipファイルを解凍し、出力されたディレクトリを任意のディレクトリに移動します。
   ※解凍ディレクトリの中にexeファイルが格納されています

## 実行手順

1. コマンドプロンプトを起動し、事前準備でダウンロードしたexeファイルの格納ディレクトリに移動します。
2. 下記コマンドをコマンドプロンプトで実行します。
   
   オプション：コンフィグファイルで有効化していないポリシーをcsvに出力するかを決定します。<br>
      *  `y` : 出力する<br>
      *  `n` : 出力しない<br>
      *  未入力 : 出力しない<br>
    ```
    ScenarioWriter <コンフィグファイルパス> <オプション>
    ```
    ```
    例：ScenarioWriter config/sample.txt y
    ```
3. コマンドプロンプトに、`csvが生成されました`と表示されると完了です。

# 開発環境
本ツールの開発環境は以下の通りです。

## 環境

* OS : Windows 10
* python : 3.7.4
* git : 2.20.1 (Apple Git-117)
* pip : 19.1.1
 
## 環境構築手順

### pythonのインストール

1. pythonを[公式サイト](https://www.python.org/downloads/windows/)からインストールします。 
   * [参考URL](https://www.python.jp/install/windows/install_py3.html)
2. 環境変数を設定します。
   * 詳しくは[ツールの使用方法の項番5](#ツールの使用方法)へ

### gitのインストール

1.  [https://git-for-windows.github.io/](https://git-for-windows.github.io/)よりgitをインストールします。
    * [参考URL](https://prog-8.com/docs/git-env-win)

### その他作業
0. コマンドプロンプトを起動します。
1. 作業用ディレクトリを作成します。
    * `mkdir ディレクトリ名`
        * サンプルコマンド：`mkdir C:\test`
2. 作成したディレクトリに移動します。
    * `cd ディレクトリ名`
        * サンプルコマンド：`cd C:\test`
3. 作成したディレクトリに本リポジトリをcloneします。
    * `git clone https://github.com/ap-communications/NEEDLEWORK-ScenarioWriter.git`
4. 作成されたディレクトリに移動します。
    * `cd NEEDLEWORK-ScenarioWriter`
5. 環境変数に設定するパス（カレントディレクトリの絶対パス）を表示します。
    * `cd`
6. 「5.」で表示したパスを環境変数に設定します。
    * `setx PYTHONPATH 5.で表示したパス`
        * サンプルコマンド：`setx PYTHONPATH C:\test\NEEDLEWORK-ScenarioWriter`
7. PCを再起動します。
8. コマンドプロンプトを起動します。
9. ツールに使用する外部ライブラリをインストールします。
    * `python -m pip install pandas==0.25.0`
10. 「4.」で作成されたディレクトリに移動します。
    * `cd 4.で作成されたディレクトリ`
        * サンプルコマンド：`cd C:\test\NEEDLEWORK-ScenarioWriter`
11. コマンドプロンプトにて以下のコマンドを実行し、シナリオCSVを出力します。
    * `python main\gencsv.py file_name disable_policy_output`   
      * file_name:ファイアウォールのコンフィグファイルを相対パスまたは絶対パスで入力、またはドラッグ&ドロップします。
      * disable_policy_output:コンフィグファイルで有効化していないポリシーをcsvに出力するかを決定します。
        * `y` : 出力する
        * `n` : 出力しない
        * 未入力 : 出力しない
        * サンプルコマンド ： `python main\gencsv.py SSGconfig.txt y`

# お問い合わせ
* 改善・要望等ございましたらpull requestをお願いします。

