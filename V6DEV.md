# メモ
## [IPv6](https://tex2e.github.io/rfc-translater/html/rfc8200.html)
- Addresses
    - スコープの概念: ICMPエラーメッセージでも使用
        - ユニキャスト・エニーキャスト
            
            → リンクローカルスコープ・グローバルスコープ
            
            ULA は fc00::/7 でグローバルスコープに当たる
            
    - マルチキャスト
    - エニーキャスト: 特別何か実装する必要があるのか？
    - link-local address の自動生成
    - 特殊アドレス
        - Unspecified Address（::/128）
            - 割り当て不可・宛先にも不可
        - Loopback Address（::1/128）
            - 物理インターフェースから受け取ったら破棄
        - Multicast Address（ff00::/8）
            - Link Local All Nodes（ff02::1）
            - Link Local All Routers（ff02::2）
        - Link-local Unicast Address（fe80::/10）
        - これら以外が Global Unicast Address
- Header
    - plen: 拡張ヘッダもペイロードとする
    - hlimの確認: 0なら破棄
    - 拡張ヘッダをしゃべれない場合は破棄してICMP code 1を送信
- Extention Header (need supp)
    - Hop-by-Hop
    - Fragment
    - Routing
    - IP Auth
    - チェックサムは？
- 上位層への影響
    - MSSが小さくなることによるバッファサイズの変更
- アドレス設定方法
    - SLAAC
    - DHCPv6
    - 手動

## [ICMPv6](https://tex2e.github.io/rfc-translater/html/rfc4443.html)
- エラーメッセージには、0〜127のメッセージタイプがあります。
    - 1: Destination Unreachable
        - code
            - 0: No route to destination
                - ルーティングテーブルに一致するエントリがない場合はcode 0を返す（デフォルトルートを持たない場合のみ発生）
            - 1: Communication with destination administratively prohibited
                - ファイアウォールでフィルタされた場合はcode 1を返す
            - 2: Beyond scope of source address
                - 「送信元アドレスのスコープ < 宛先アドレスのスコープ」の場合に発生
                - 例）Src: link-local, Dst: global-scope
            - 3: Address unreachable
                - router or originating node
            - 4: Port unreachable
                - トランスポート層にリスナーがいない場合
            - 5: Source address failed ingress/egress policy
            - 6: Reject route to destination
    - 2: Packet Too Big
        - code
            - 0: Seto to zero
                - next-hop リンクのMTUをセット
                - PMTUの一部で利用
    - 3: Time Exceeded
        - code
            - 0: Hop limit exceeded in transit
                - ルータがhlim 0でパケットを受信した場合，または0に減らす場合にパケットを破棄して通知
            - 1: Fragment reassembly time exceeded
    - 4: Param Problem
        - code
            - 0: 誤ったヘッダフィールドを発見
            - 1: 知らないnext-headerに遭遇した
            - 2: 知らないIPv6 optionを発見
        - Pointer Field: エラーが見つかったパケット内のオフセットを示す
- 情報メッセージには、128〜255のメッセージタイプがあります。
    - 128: Echo Req
        - code
            - 0: zero
                - sequence number: zeroでも良い
                - data: 任意のデータ
    - 129: Echo Reply
        - code
            - 0: zero
                - sequence number:
                - data: echo reqのデータ←修正したらダメ！
            - IPv6マルチキャスト，Anycastアドレス宛でも返事する
                - 返信のソースアドレスは、エコー要求メッセージが受信されたインターフェイスに属するユニキャストアドレスでなければなりません。
- Path MTU Discovery:  https://tex2e.github.io/rfc-translater/html/rfc8201.html
- ND6（Neighbor Discovery for IP version 6 (IPv6)）: https://tex2e.github.io/rfc-translater/html/rfc4861.html
- MLD6

## [Socket APIのIPv6対応](https://tex2e.github.io/rfc-translater/html/rfc3542.html)

## Others
- ネットワークデバイス
    - Ethernet Multicast Address
        - 「33:33:〜」が必須: Filterなのか？
            - accept list 的な
- 論理インターフェース（IPv6）
    - scope
    - is router
    - is anycast
    - multicast filter ← マルチキャスト受け取れるように
        - MACアドレスから生成するものもある