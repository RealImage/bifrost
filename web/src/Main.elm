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
import Html.Attributes as Attr exposing (alt, class, src)
import Html.Events exposing (onClick)
import Http
import Json.Decode as Decode
import RemoteData exposing (RemoteData(..), WebData)
import Task
import UUID exposing (UUID)


type alias Model =
    { nss : RemoteData String (List UUID)
    , ns : Maybe UUID
    , ids : Array (RemoteData String Identity)
    }


type alias Identity =
    { key : String
    , crt : String
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { nss = Loading
      , ns = Nothing
      , ids = Array.empty
      }
    , Http.get { expect = Http.expectString GotNss, url = "/namespaces" }
    )


type Msg
    = GotNss (Result Http.Error String)
    | ChangedNs UUID
    | OpenFilesClicked
    | FilesSelected File (List File)
    | FileRead String
    | IdRequested
    | GotCsr Decode.Value
    | GotId String (WebData String)


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        gotNss : Result Http.Error String -> RemoteData String (List UUID)
        gotNss res =
            let
                f : String -> RemoteData String (List UUID) -> RemoteData String (List UUID)
                f n a =
                    if RemoteData.isFailure a then
                        a

                    else
                        case UUID.fromString n of
                            Ok ns ->
                                RemoteData.map (List.append [ ns ]) a

                            Err _ ->
                                RemoteData.Failure <| "Error parsing UUID: " ++ n
            in
            case res of
                Ok s ->
                    String.lines s
                        |> List.filter (not << String.isEmpty)
                        |> List.foldr f (RemoteData.Success [])

                Err _ ->
                    Failure "Error fetching namespace"

        askCsr : Maybe UUID -> Maybe String -> Cmd msg
        askCsr n k =
            case n of
                Just ns ->
                    Csr.generate { ns = UUID.toString ns, key = k }

                Nothing ->
                    Cmd.none

        reqCrt : Csr.Csr -> Cmd Msg
        reqCrt c =
            Http.post
                { expect = Http.expectString <| RemoteData.fromResult >> GotId c.key
                , url = "/" ++ c.ns ++ "/issue"
                , body = Http.stringBody "text/plain" c.csr
                }
    in
    case msg of
        GotNss r ->
            let
                ns =
                    gotNss r

                c =
                    case ns of
                        Success (n :: _) ->
                            Just n

                        _ ->
                            Nothing
            in
            ( { model | ns = c, nss = ns }, Cmd.none )

        ChangedNs ns ->
            ( { model | ns = Just ns }, Cmd.none )

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
            ( model, askCsr model.ns <| Just k )

        IdRequested ->
            ( model, askCsr model.ns Nothing )

        GotCsr v ->
            case Decode.decodeValue Csr.replyDecoder v of
                Ok r ->
                    case r of
                        Ok c ->
                            ( model, reqCrt c )

                        Err e ->
                            ( { model | ids = Array.push (Failure e) model.ids }
                            , Cmd.none
                            )

                Err e ->
                    ( { model | ids = Array.push (Failure <| Decode.errorToString e) model.ids }
                    , Cmd.none
                    )

        GotId k c ->
            case c of
                Success crt ->
                    ( { model | ids = Array.push (Success { key = k, crt = crt }) model.ids }
                    , Cmd.none
                    )

                Failure _ ->
                    ( { model | ids = Array.push (Failure "Error creating identity") model.ids }
                    , Cmd.none
                    )

                _ ->
                    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Csr.receive GotCsr


view : Model -> Browser.Document Msg
view model =
    let
        ( title, body ) =
            case model.nss of
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
                    , viewIssuer model ns
                    )
    in
    { title = title
    , body = body
    }


viewIssuer : Model -> List UUID -> List (Html Msg)
viewIssuer model nss =
    let
        cns : String
        cns =
            case model.ns of
                Just n ->
                    UUID.toString n

                Nothing ->
                    "Not selected"

        nsOpt : String -> Html Msg
        nsOpt ns =
            let
                o : List (Html.Attribute Msg) -> Html Msg
                o a =
                    Html.option (Attr.value ns :: a) [ text ns ]
            in
            if cns == ns then
                o [ Attr.selected True ]

            else
                o []
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
        , Html.div [ class "nav-right" ] [ Html.a [] [ text cns ] ]
        ]
    , Html.header [ class "container" ]
        [ Html.node "hgroup"
            []
            [ Html.h1 [] [ text "Certificate Issuer" ]
            , Html.p [] [ text "Hot off the presses" ]
            ]
        , Html.section []
            [ Html.h2 [] [ text "Select namespace" ]
            , Html.select [] <| List.map (UUID.toString >> nsOpt) nss
            ]
        , Html.section []
            [ Html.h2 [] [ text "New" ]
            , Html.button
                [ class "button", onClick IdRequested ]
                [ text "Create" ]
            , Html.button
                [ class "button", onClick OpenFilesClicked ]
                [ text "Upload" ]
            ]
        ]
    , main_ [ class "container" ]
        [ Html.section []
            [ Html.h2 [] [ text "Identities" ]
            , Html.div [ class "row" ] <| Array.foldl viewRequests [] model.ids
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
                , Html.h4 [] [ text "Certificate" ]
                , Html.p [] [ text i.crt ]
                ]
                :: acc

        Failure e ->
            Html.article
                [ class "card" ]
                [ Html.p [] [ Html.pre [] [ text e ] ] ]
                :: acc


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = subscriptions
        , update = update
        , view = view
        }
