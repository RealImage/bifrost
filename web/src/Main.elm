{-
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/.
-}


module Main exposing (Identity, Model, Msg, main)

import Array exposing (Array)
import Browser
import Csr
import File exposing (File)
import File.Select
import Html exposing (Html, main_, text)
import Html.Attributes exposing (alt, class, src)
import Html.Events exposing (onClick)
import Http
import Json.Decode as Decode
import RemoteData exposing (RemoteData(..), WebData)
import Task
import UUID exposing (UUID)


type alias Model =
    { namespace : RemoteData String UUID
    , requests : Array (RemoteData String Identity)
    }


type alias Identity =
    { uuid : String
    , key : String
    , crt : String
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { namespace = Loading
      , requests = Array.empty
      }
    , Http.get { expect = Http.expectString GotNamespace, url = "/namespace" }
    )


type Msg
    = GotNamespace (Result Http.Error String)
    | OpenFilesClicked
    | FilesSelected File (List File)
    | FileRead String
    | IdentityRequested
    | GotCSR Decode.Value
    | GotIdentity String String (WebData String)


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        askCsr : RemoteData String UUID -> Maybe String -> Cmd msg
        askCsr n k =
            case n of
                Success ns ->
                    Csr.generate { namespace = UUID.toString ns, key = k }

                _ ->
                    Cmd.none
    in
    case msg of
        GotNamespace r ->
            ( { model | namespace = gotNamespace r }, Cmd.none )

        OpenFilesClicked ->
            let
                mimes : List String
                mimes =
                    [ "application/octet-stream", "text/plain", ".pem", ".der", ".cer", ".crt" ]
            in
            ( model, File.Select.files mimes FilesSelected )

        FilesSelected file files ->
            let
                readFile : File -> Cmd Msg
                readFile f =
                    Task.perform FileRead <| File.toString f
            in
            ( model, Cmd.batch <| List.map readFile <| file :: files )

        FileRead k ->
            ( model, askCsr model.namespace <| Just k )

        IdentityRequested ->
            ( model, askCsr model.namespace Nothing )

        GotCSR v ->
            case Decode.decodeValue Csr.replyDecoder v of
                Ok r ->
                    case r of
                        Ok c ->
                            ( model, requestCrt c )

                        Err e ->
                            ( { model
                                | requests =
                                    Array.push (Failure e) model.requests
                              }
                            , Cmd.none
                            )

                Err e ->
                    ( { model
                        | requests =
                            Array.push (Failure <| Decode.errorToString e) model.requests
                      }
                    , Cmd.none
                    )

        GotIdentity u k c ->
            case c of
                Success crt ->
                    let
                        success : RemoteData String Identity
                        success =
                            Success { uuid = u, key = k, crt = crt }
                    in
                    ( { model | requests = Array.push success model.requests }, Cmd.none )

                Failure _ ->
                    let
                        failure : RemoteData String Identity
                        failure =
                            Failure "error creating identity"
                    in
                    ( { model | requests = Array.push failure model.requests }, Cmd.none )

                _ ->
                    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Csr.receive GotCSR


requestCrt : Csr.Csr -> Cmd Msg
requestCrt c =
    Http.post
        { expect = Http.expectString <| RemoteData.fromResult >> GotIdentity c.uuid c.key
        , url = "/issue"
        , body = Http.stringBody "text/plain" c.csr
        }


gotNamespace : Result Http.Error String -> RemoteData String UUID
gotNamespace res =
    case res of
        Ok s ->
            case UUID.fromString s of
                Ok uuid ->
                    Success uuid

                Err _ ->
                    Failure "Error parsing namespace"

        Err _ ->
            Failure "Error fetching namespace"


view : Model -> Browser.Document Msg
view model =
    let
        ( title, body ) =
            case model.namespace of
                NotAsked ->
                    ( "", [] )

                Loading ->
                    ( "Bifrost", [ Html.text "Loading" ] )

                Failure e ->
                    ( "zen meditation error"
                    , [ Html.h1 [] [ text e ] ]
                    )

                Success ns ->
                    ( "Bifrost Certificate Issuer"
                    , viewIssuer model <| UUID.toString ns
                    )
    in
    { title = title
    , body = body
    }


viewIssuer : Model -> String -> List (Html Msg)
viewIssuer model ns =
    [ Html.nav [ class "nav" ]
        [ Html.div
            [ class "nav-left" ]
            [ Html.a
                [ class "brand" ]
                [ Html.img [ src "/bifrost.webp", alt "Bifrost" ] []
                , text "Bifrost"
                ]
            ]
        , Html.div
            [ class "nav-right" ]
            [ Html.a [] [ text ns ] ]
        ]
    , Html.header [ class "container" ]
        [ Html.node "hgroup"
            []
            [ Html.h1 [] [ text "Certificate Issuer" ]
            , Html.p [] [ text "Hot off the presses" ]
            ]
        , Html.section []
            [ Html.h2 [] [ text "New" ]
            , Html.button
                [ class "button", onClick IdentityRequested ]
                [ text "Create" ]
            , Html.button
                [ class "button", onClick OpenFilesClicked ]
                [ text "Upload" ]
            ]
        ]
    , main_ [ class "container" ]
        [ Html.section []
            [ Html.h2 [] [ text "Identities" ]
            , Html.div [ class "row" ] <| Array.foldl viewRequests [] model.requests
            ]
        ]
    ]


viewRequests : RemoteData String Identity -> List (Html a) -> List (Html a)
viewRequests r acc =
    case r of
        NotAsked ->
            acc

        Loading ->
            Html.article [ class "card" ] [ Html.p [] [ text "Loading" ] ] :: acc

        Success i ->
            Html.article [ class "card" ]
                [ Html.header [] [ Html.h3 [] [ text "Identity" ] ]
                , Html.h4 [] [ text "UUID" ]
                , Html.p [] [ text i.uuid ]
                , Html.h4 [] [ text "Certificate" ]
                , Html.p [] [ text i.crt ]
                ]
                :: acc

        Failure e ->
            Html.article [ class "card" ] [ Html.p [] [ text e ] ] :: acc


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = subscriptions
        , update = update
        , view = view
        }
