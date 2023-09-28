{-
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/.
-}


module Main exposing (Identity, Model, Msg, main)

import Browser
import Csr
import Dict exposing (Dict)
import File exposing (File)
import File.Select
import Html exposing (Html, main_, text)
import Html.Attributes as Attr exposing (alt, class, src)
import Html.Events exposing (onClick)
import Http
import Json.Decode as Decode
import RemoteData exposing (RemoteData(..), WebData)
import Task
import UUID exposing (UUID)


type alias Model =
    { ns : RemoteData String UUID
    , ids : Dict String Identity
    , errors : Maybe String
    }


type alias Identity =
    { key : String
    , csr : String
    , crts : List (WebData String)
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { ns = Loading
      , ids = Dict.empty
      , errors = Nothing
      }
    , Http.get { expect = Http.expectString GotNs, url = "/namespace" }
    )


type Msg
    = GotNs (Result Http.Error String)
    | OpenFilesClicked
    | FilesSelected File (List File)
    | FileRead String
    | IdAsked
    | GotCsr Decode.Value
    | GotId Csr.Csr (WebData String)


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        gotNs : Result Http.Error String -> RemoteData String UUID
        gotNs res =
            case res of
                Ok s ->
                    case UUID.fromString s of
                        Ok ns ->
                            RemoteData.Success ns

                        Err _ ->
                            RemoteData.Failure <| "Error parsing UUID: " ++ s

                Err _ ->
                    Failure "Error fetching namespace"

        reqCrt : Csr.Csr -> Cmd Msg
        reqCrt c =
            Http.post
                { expect = Http.expectString <| RemoteData.fromResult >> GotId c
                , url = "/issue"
                , body = Http.stringBody "text/plain" c.csr
                }
    in
    case msg of
        GotNs r ->
            ( { model | ns = gotNs r }, Cmd.none )

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
            case model.ns of
                RemoteData.Success n ->
                    ( model, Csr.generate { ns = UUID.toString n, key = Just k } )

                _ ->
                    ( model, Cmd.none )

        GotCsr v ->
            case Decode.decodeValue Csr.decoder v of
                -- TODO: handle errors
                Ok r ->
                    case r of
                        Ok c ->
                            ( model, reqCrt c )

                        _ ->
                            ( model, Cmd.none )

                Err _ ->
                    ( model, Cmd.none )

        IdAsked ->
            case model.ns of
                RemoteData.Success n ->
                    ( model, Csr.generate { ns = UUID.toString n, key = Nothing } )

                _ ->
                    ( model, Cmd.none )

        GotId csr crt ->
            let
                ids : Dict String Identity
                ids =
                    Dict.update (UUID.toString csr.id)
                        (\a ->
                            case a of
                                Just id ->
                                    Just { id | crts = crt :: id.crts }

                                Nothing ->
                                    Just { key = csr.key, csr = csr.csr, crts = [ crt ] }
                        )
                        model.ids
            in
            ( { model | ids = ids }, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Csr.receive GotCsr


view : Model -> Browser.Document Msg
view model =
    let
        ( title, body ) =
            case model.ns of
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
                    , viewIssuer ns model.ids
                    )
    in
    { title = title
    , body = body
    }


viewIssuer : UUID -> Dict String Identity -> List (Html Msg)
viewIssuer ns ids =
    let
        cns : String
        cns =
            UUID.toString ns
    in
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
            [ Html.a []
                [ Html.p []
                    [ Html.span [] [ text "Namespace " ]
                    , Html.strong [ class "text-primary" ] [ text cns ]
                    ]
                ]
            ]
        ]
    , Html.header [ class "container" ]
        [ Html.node "hgroup"
            []
            [ Html.h1 [] [ text "Certificate Issuer" ]
            , Html.p [] [ text "Hot off the presses!" ]
            ]
        ]
    , main_ [ class "container" ]
        [ Html.section []
            [ Html.h2 [] [ text "Keys" ]
            , Html.button
                [ class "button bg-primary text-white", onClick IdAsked ]
                [ text "Generate" ]
            , Html.button
                [ class "button bg-dark text-white", onClick OpenFilesClicked ]
                [ text "Upload" ]
            ]
        , Html.section []
            [ Html.h2 [] [ text "Identities" ]
            , Html.div [ class "row" ] <| Dict.foldl viewIds [] ids
            ]
        ]
    ]


viewIds : String -> Identity -> List (Html a) -> List (Html a)
viewIds id ident acc =
    let
        pcv : String -> String -> Html a
        pcv name crt =
            Html.node name
                [ Attr.attribute "certificate" crt, Attr.attribute "download" "true" ]
                []

        viewCrt : WebData String -> Html a
        viewCrt crt =
            case crt of
                NotAsked ->
                    Html.p [] [ text "Not asked" ]

                Loading ->
                    Html.p [] [ text "Loading" ]

                Failure e ->
                    case e of
                        Http.BadStatus _ ->
                            Html.p [] [ text "Bad status" ]

                        Http.Timeout ->
                            Html.p [] [ text "Timeout" ]

                        Http.NetworkError ->
                            Html.p [] [ text "Network error" ]

                        Http.BadBody _ ->
                            Html.p [] [ text "Bad body" ]

                        Http.BadUrl _ ->
                            Html.p [] [ text "Bad URL" ]

                Success c ->
                    Html.details []
                        [ Html.summary [] [ text "Certificate" ]
                        , pcv "peculiar-certificate-viewer" c
                        ]
    in
    Html.article [ class "card" ]
        [ Html.header [] [ Html.strong [] [ text id ] ]
        , Html.details []
            [ Html.summary [] [ text "Certificate Request" ]
            , pcv "peculiar-csr-viewer" ident.csr
            ]
        , Html.div [] <| List.map viewCrt ident.crts
        , Html.footer []
            [ Html.button
                [ class "button" ]
                [ text "Request Certificate" ]
            ]
        ]
        :: acc


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = subscriptions
        , update = update
        , view = view
        }
