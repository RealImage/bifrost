port module CSR exposing (..)

import Json.Decode as Decode
import Json.Encode as Encode
import RemoteData exposing (RemoteData)


port generate : Request -> Cmd msg


port receive : (Decode.Value -> msg) -> Sub msg


type alias Request =
    { namespace : String
    , key : Maybe String
    }


type alias Response =
    { uuid : String
    , key : String
    , csr : String
    }


encoder : Request -> Encode.Value
encoder r =
    Encode.object
        [ ( "namespace", Encode.string r.namespace )
        , ( "key", Maybe.withDefault Encode.null <| Maybe.map Encode.string r.key )
        ]


decoder : Decode.Decoder Response
decoder =
    Decode.map3 Response
        (Decode.field "uuid" Decode.string)
        (Decode.field "key" Decode.string)
        (Decode.field "csr" Decode.string)


generated : (RemoteData Decode.Error Response -> msg) -> Decode.Value -> msg
generated tag =
    Decode.decodeValue decoder
        >> RemoteData.fromResult
        >> tag
