{-
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/.
-}


module Main exposing (Identity, Model, Msg(..), main)

import Array exposing (Array)
import Browser
import CSR
import File exposing (File)
import File.Select
import Html exposing (Html, main_, text)
import Html.Attributes exposing (alt, class, src)
import Html.Events exposing (onClick)
import Http
import Json.Decode as Decode
import RemoteData exposing (RemoteData, WebData)
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
    ( { namespace = RemoteData.Loading
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
            ( model, generateCSR model.namespace <| Just k )

        IdentityRequested ->
            ( model, generateCSR model.namespace Nothing )

        GotCSR v ->
            case Decode.decodeValue CSR.decoder v of
                Ok r ->
                    case r of
                        Result.Ok c ->
                            ( model, getCertificate c )

                        Result.Err e ->
                            ( { model
                                | requests =
                                    Array.push (RemoteData.Failure e) model.requests
                              }
                            , Cmd.none
                            )

                Err _ ->
                    ( { model
                        | requests =
                            Array.push (RemoteData.Failure "zen meditation error") model.requests
                      }
                    , Cmd.none
                    )

        GotIdentity u k c ->
            case c of
                RemoteData.Success crt ->
                    let
                        success : RemoteData String Identity
                        success =
                            RemoteData.Success { uuid = u, key = k, crt = crt }
                    in
                    ( { model | requests = Array.push success model.requests }, Cmd.none )

                RemoteData.Failure _ ->
                    let
                        failure : RemoteData String Identity
                        failure =
                            RemoteData.Failure "error creating identity"
                    in
                    ( { model | requests = Array.push failure model.requests }, Cmd.none )

                _ ->
                    ( model, Cmd.none )


generateCSR : RemoteData String UUID -> Maybe String -> Cmd Msg
generateCSR n k =
    case n of
        RemoteData.Success ns ->
            CSR.generate { namespace = UUID.toString ns, key = k }

        _ ->
            Cmd.none


subscriptions : Model -> Sub Msg
subscriptions _ =
    CSR.receive GotCSR


getCertificate : CSR.Response -> Cmd Msg
getCertificate r =
    Http.post
        { expect = Http.expectString <| GotIdentity r.uuid r.key << RemoteData.fromResult
        , url = "/issue"
        , body = Http.stringBody "text/plain" r.csr
        }


gotNamespace : Result Http.Error String -> RemoteData String UUID
gotNamespace res =
    case res of
        Result.Ok s ->
            case UUID.fromString s of
                Result.Ok uuid ->
                    RemoteData.Success uuid

                Result.Err _ ->
                    RemoteData.Failure "Error parsing namespace"

        Result.Err _ ->
            RemoteData.Failure "Error fetching namespace"


view : Model -> Browser.Document Msg
view model =
    let
        ( title, body ) =
            case model.namespace of
                RemoteData.NotAsked ->
                    ( "", [] )

                RemoteData.Loading ->
                    ( "Bifrost", [ Html.text "Loading" ] )

                RemoteData.Failure e ->
                    ( "zen meditation error"
                    , [ Html.h1 [] [ text e ] ]
                    )

                RemoteData.Success ns ->
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
        RemoteData.NotAsked ->
            acc

        RemoteData.Loading ->
            Html.article [ class "card" ] [ Html.p [] [ text "Loading" ] ] :: acc

        RemoteData.Success i ->
            Html.article [ class "card" ]
                [ Html.header [] [ Html.h3 [] [ text "Identity" ] ]
                , Html.h4 [] [ text "UUID" ]
                , Html.p [] [ text i.uuid ]
                , Html.h4 [] [ text "Certificate" ]
                , Html.p [] [ text i.crt ]
                ]
                :: acc

        RemoteData.Failure e ->
            Html.article [ class "card" ] [ Html.p [] [ text e ] ] :: acc


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = subscriptions
        , update = update
        , view = view
        }
