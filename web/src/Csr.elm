{-
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/.
-}


port module Csr exposing (Csr, Gen, decoder, generate, receive)

import Json.Decode as D
import UUID exposing (UUID)


type alias Gen =
    { ns : String
    , key : Maybe String
    }


type alias Csr =
    { id : UUID
    , key : String
    , csr : String
    }


port generate : Gen -> Cmd msg


port receive : (D.Value -> msg) -> Sub msg


uuidDecoder : D.Decoder UUID
uuidDecoder =
    D.string
        |> D.andThen
            (\str ->
                case UUID.fromString str of
                    Ok uuid ->
                        D.succeed uuid

                    Err err ->
                        case err of
                            UUID.WrongFormat ->
                                D.fail "Wrong UUID format"

                            UUID.WrongLength ->
                                D.fail "Wrong UUID length"

                            UUID.UnsupportedVariant ->
                                D.fail "Unsupported UUID variant"

                            UUID.IsNil ->
                                D.fail "UUID is nil"

                            UUID.NoVersion ->
                                D.fail "UUID has no version"
            )


decoder : D.Decoder (Result String Csr)
decoder =
    let
        d : D.Decoder Csr
        d =
            D.map3 Csr
                (D.field "id" uuidDecoder)
                (D.field "key" D.string)
                (D.field "csr" D.string)
    in
    D.oneOf
        [ D.map Ok d
        , D.map Err (D.field "error" D.string)
        ]
