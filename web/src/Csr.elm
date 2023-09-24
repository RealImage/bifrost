{-
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/.
-}


port module Csr exposing (Csr, RawKey, generate, receive, replyDecoder)

import Json.Decode as D


type alias RawKey =
    { namespace : String
    , key : Maybe String
    }


type alias Csr =
    { uuid : String
    , key : String
    , csr : String
    }


port generate : RawKey -> Cmd msg


port receive : (D.Value -> msg) -> Sub msg


replyDecoder : D.Decoder (Result String Csr)
replyDecoder =
    D.oneOf
        [ D.map Ok decoder
        , D.map Err (D.field "error" D.string)
        ]


decoder : D.Decoder Csr
decoder =
    D.map3 Csr
        (D.field "uuid" D.string)
        (D.field "key" D.string)
        (D.field "csr" D.string)
