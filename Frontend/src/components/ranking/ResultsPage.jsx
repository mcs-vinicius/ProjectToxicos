import React, { useEffect, useState } from "react";
import axios from "axios";
import "../../styles/ResultsPage.css";

const ResultsPage = () => {
  const [seasons, setSeasons] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    async function fetchSeasons() {
      try {
        const apiUrl = import.meta.env.VITE_API_URL;
        const response = await axios.get(`${apiUrl}/seasons`);
        const data = response.data;
        setSeasons(data);

        if (data.length > 0) {
          setCurrentPage(data.length);
        }
      } catch (error) {
        console.error("Erro ao buscar temporadas:", error);
      }
    }
    fetchSeasons();
  }, []);

  const totalPages = seasons.length;
  const season = seasons[currentPage - 1];

  const getRankingData = (participants) => {
    const sortedByFase = [...participants].sort((a, b) => b.fase - a.fase);
    const top30Fase = sortedByFase.slice(0, 30);
    const remainingFase = sortedByFase.slice(30);
    const sumFase = top30Fase.reduce((acc, p) => acc + p.fase, 0);

    const sortedByTotal = [...participants]
      .map((p) => ({ ...p, total: p.r1 + p.r2 + p.r3 }))
      .sort((a, b) => b.total - a.total);
    const top30Total = sortedByTotal.slice(0, 30);
    const remainingTotal = sortedByTotal.slice(30);
    const sumTotal = top30Total.reduce((acc, p) => acc + p.total, 0);

    return {
      top30Fase,
      remainingFase,
      sumFase,
      top30Total,
      remainingTotal,
      sumTotal,
    };
  };

  const rankingData = season ? getRankingData(season.participants) : null;

  const calculateEvolution = (participantName, currentSeasonIndex) => {
    if (currentSeasonIndex <= 0 || seasons.length <= 1) {
      return "-";
    }

    const currentSeason = seasons[currentSeasonIndex];
    const previousSeason = seasons[currentSeasonIndex - 1];
    
    if (!currentSeason || !previousSeason) return "-";

    const currentParticipant = currentSeason.participants.find(p => p.name === participantName);
    const previousParticipant = previousSeason.participants.find(p => p.name === participantName);

    if (currentParticipant && previousParticipant) {
      const evolution = currentParticipant.fase - previousParticipant.fase;
      return evolution;
    }
    return "-";
  };
 
  const formatDateBR = (dateString) => {
    if (!dateString) return 'Data não definida';
    const options = { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' };
    return new Date(dateString).toLocaleDateString('pt-BR', options);
  };

  const renderEvolution = (participantName) => {
    const evolution = calculateEvolution(participantName, currentPage - 1);
    const isNumeric = typeof evolution === 'number';
    
    let evolutionClass = 'evolution-neutral';
    if (isNumeric) {
        if (evolution > 0) evolutionClass = 'evolution-positive';
        if (evolution < 0) evolutionClass = 'evolution-negative';
    }
    
    const evolutionText = isNumeric && evolution > 0 ? `+${evolution}` : evolution;

    return <td className={evolutionClass}>{evolutionText}</td>;
  };

  return (
    <div className="container">
      <h1 className="title">Expedição Lunar</h1>

      {season && rankingData ? (
        <>
          <div className="season-info">
            Temporada {currentPage} - {formatDateBR(season.start_date)} até{" "}
            {formatDateBR(season.end_date)}
          </div>

          <div className="tables-container">
            <div className="table-wrapper">
              <div className="table-title">Rank de Acesso</div>
              <table>
                <thead>
                  <tr>
                    <th>Posição</th>
                    <th>Nome</th>
                    <th>Fase de Acesso</th>
                    <th>Evolução</th>
                  </tr>
                </thead>
                <tbody>
                  {/* Top 30 Ativos */}
                  {rankingData.top30Fase.map((p, i) => (
                    <tr key={p.id || i}>
                      <td>{i + 1}º</td>
                      <td className="leftlabel" data-label="Nome">{p.name}</td>
                      <td data-label="Fase">{p.fase}</td>
                      {renderEvolution(p.name)}
                    </tr>
                  ))}
                  {/* Restante Inativo (com evolução) */}
                  {rankingData.remainingFase.map((p, i) => (
                      <tr key={p.id || i} className="inactive-participant">
                          <td>{30 + i + 1}º</td>
                          <td className="leftlabel" data-label="Nome">{p.name}</td>
                          <td data-label="Fase">{p.fase}</td>
                          {renderEvolution(p.name)}
                      </tr>
                  ))}
                </tbody>
                <tfoot>
                    <tr>
                        <td colSpan="2">Total (Top 30)</td>
                        <td colSpan="2"><span className="txtcenter">{rankingData.sumFase.toLocaleString('pt-BR')}</span></td>
                    </tr>
                </tfoot>
              </table>
            </div>

            <div className="table-wrapper">
              <div className="table-title">Expedição Lunar</div>
              <table>
                <thead>
                  <tr>
                    <th>Posição</th>
                    <th>Nome</th>
                    <th>1ª Rodada</th>
                    <th>2ª Rodada</th>
                    <th>3ª Rodada</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {/* Top 30 Ativos */}
                  {rankingData.top30Total.map((p, i) => (
                    <tr key={p.id || i}>
                      <td >{i + 1}º</td>
                      <td className="leftlabel">{p.name}</td>
                      <td>{p.r1}</td>
                      <td>{p.r2}</td>
                      <td>{p.r3}</td>
                      <td>{p.total}</td>
                    </tr>
                  ))}
                  {/* Restante Inativo (com pontuação) */}
                  {rankingData.remainingTotal.map((p, i) => (
                      <tr key={p.id || i} className="inactive-participant">
                          <td>{30 + i + 1}º</td>
                          <td className="leftlabel">{p.name}</td>
                          <td>{p.r1}</td>
                          <td>{p.r2}</td>
                          <td>{p.r3}</td>
                          <td>{p.total}</td>
                      </tr>
                  ))}
                </tbody>
                <tfoot>
                    <tr>
                        <td colSpan="5">Total (Top 30)</td>
                        <td >{rankingData.sumTotal.toLocaleString('pt-BR')}</td>
                    </tr>
                </tfoot>
              </table>
            </div>
          </div>

          <div className="pagination">
            <button
              onClick={() => setCurrentPage(currentPage - 1)}
              disabled={currentPage === 1}
            >
              &lt; Anterior
            </button>
            <button
              onClick={() => setCurrentPage(currentPage + 1)}
              disabled={currentPage === totalPages}
            >
              Próximo &gt;
            </button>
          </div>
        </>
      ) : (
        <p>Nenhuma temporada encontrada. Verificando dados...</p>
      )}
    </div>
  );
};

export default ResultsPage;